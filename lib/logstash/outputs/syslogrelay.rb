# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "date"
require "logstash/codecs/plain"


# Relays events to a syslog server.
#
# You can relay messages using either UDP or 
# TCP with ot without SSL as the transport protocol.
#
# By default the contents of the `message` field will be shipped as
# the free-form message text part of the emitted syslog message. If
# your messages don't have a `message` field or if you for some other
# reason want to change the emitted message, modify the `message`
# configuration option.
class LogStash::Outputs::Syslogrelay < LogStash::Outputs::Base
  config_name "syslogrelay"


  # syslog server address to connect to
  config :host, :validate => :string, :required => true

  # syslog server port to connect to
  config :port, :validate => :number, :required => true

  # when connection fails, retry interval in sec.
  config :reconnect_interval, :validate => :number, :default => 1

  # syslog server protocol. you can choose between udp, tcp and ssl/tls over tcp
  config :protocol, :validate => ["tcp", "udp", "ssl-tcp"], :default => "udp"

  # Verify the identity of the other end of the SSL connection against the CA.
  config :ssl_verify, :validate => :boolean, :default => false

  # The SSL CA certificate, chainfile or CA path. The system CA path is automatically included.
  config :ssl_cacert, :validate => :path

  # SSL certificate path
  config :ssl_cert, :validate => :path

  # SSL key path
  config :ssl_key, :validate => :path

  # SSL key passphrase
  config :ssl_key_passphrase, :validate => :password, :default => nil

  # message text to log. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :message, :validate => :string, :default => "%{message}"

  def register
    @client_socket = nil

    if ssl?
      @ssl_context = setup_ssl
    end
    
    if @codec.instance_of? LogStash::Codecs::Plain
      if @codec.config["format"].nil?
        @codec = LogStash::Codecs::Plain.new({"format" => @message})
      end
    end
    @codec.on_event(&method(:publish))

  end

  def receive(event)
    @codec.encode(event)
  end

  def publish(event, payload)

    message = payload.to_s.rstrip.gsub(/[\r][\n]/, "\n").gsub(/[\n]/, '\n')

    syslog_msg = "#{message}"

    begin
      @client_socket ||= connect
      @client_socket.write(syslog_msg + "\n")
    rescue => e
      # We don't expect udp connections to fail because they are stateless, but ...
      # udp connections may fail/raise an exception if used with localhost/127.0.0.1
      return if udp?

      @logger.warn("syslog " + @protocol + " output exception: closing, reconnecting and resending event", :host => @host, :port => @port, :exception => e, :backtrace => e.backtrace, :event => event)
      @client_socket.close rescue nil
      @client_socket = nil

      sleep(@reconnect_interval)
      retry
    end
  end

  private

  def udp?
    @protocol == "udp"
  end

  def ssl?
    @protocol == "ssl-tcp"
  end

  def connect
    socket = nil
    if udp?
      socket = UDPSocket.new
      socket.connect(@host, @port)
    else
      socket = TCPSocket.new(@host, @port)
      if ssl?
        socket = OpenSSL::SSL::SSLSocket.new(socket, @ssl_context)
        begin
          socket.connect
        rescue OpenSSL::SSL::SSLError => ssle
          @logger.error("SSL Error", :exception => ssle,
                        :backtrace => ssle.backtrace)
          # NOTE(mrichar1): Hack to prevent hammering peer
          sleep(5)
          raise
        end
      end
    end
    socket
  end

  def setup_ssl
    require "openssl"
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_cert))
    ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key),@ssl_key_passphrase)
    if @ssl_verify
      cert_store = OpenSSL::X509::Store.new
      # Load the system default certificate path to the store
      cert_store.set_default_paths
      if File.directory?(@ssl_cacert)
        cert_store.add_path(@ssl_cacert)
      else
        cert_store.add_file(@ssl_cacert)
      end
      ssl_context.cert_store = cert_store
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    end
    ssl_context
  end
end
