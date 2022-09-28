# ZeroTrace

Go package ZeroTrace implements the
[0trace](https://seclists.org/fulldisclosure/2007/Jan/145)
traceroute technique which determines the round trip time to an IP address that
won't respond to ICMP echo requests.  It does so by taking advantage of an
already-established TCP connection to the target, and injecting packets with
increasing TTL into that connection.

## Configuration

ZeroTrace's
[constructor](https://pkg.go.dev/github.com/brave-experiments/zerotrace#NewZeroTrace)
expects a configuration object as argument.  Take a look at the
[`Config`](https://pkg.go.dev/github.com/brave-experiments/zerotrace#Config)
struct to learn more about configuration options.  The function
[`NewDefaultConfig`](https://pkg.go.dev/github.com/brave-experiments/zerotrace#NewDefaultConfig)
returns a default configuration object with reasonable defaults.

## Example

Use the code in the [example](example/) directory to get started.

## Development

To test and lint the code, run:

    make
