# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/syslogrelay"
require "logstash/codecs/plain"
require "json"

describe LogStash::Outputs::Syslogrelay do

  it "should register without errors" do
    plugin = LogStash::Plugin.lookup("output", "syslogrelay").new({"host" => "foo", "port" => "123"})
    expect { plugin.register }.to_not raise_error
  end

  subject do
    plugin = LogStash::Plugin.lookup("output", "syslogrelay").new(options)
    plugin.register
    plugin
  end

  let(:socket) { double("fake socket") }
  let(:event) { LogStash::Event.new({"message" => "bar", "host" => "baz"}) }

  shared_examples "syslogrelay output" do
    it "should write expected format" do
      expect(subject).to receive(:connect).and_return(socket)
      expect(socket).to receive(:write).with(output)
      subject.receive(event)
    end
  end
end
