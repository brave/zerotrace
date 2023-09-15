# ZeroTrace

[![GoDoc](https://pkg.go.dev/badge/github.com/brave/zerotrace?utm_source=godoc)](https://pkg.go.dev/github.com/brave/zerotrace)

Imagine you run a Web service
and want to determine the network-layer round trip time to clients
that connect to your Web service.
An ICMP ping is unlikely to work
as most home routers don't respond to ICMP echo requests.
A TCP ping is also unlikely to work
because home routers typically don't respond to unexpected segments
with a TCP RST segment.
It is generally difficult to get home routers to respond to unsolicited traffic.

The key insight of the
[0trace technique](https://seclists.org/fulldisclosure/2007/Jan/145)
is to piggyback onto an already-established TCP connection
to conduct a traceroute measurement.
As long as the client has an open TCP connection to our Web service,
we can inject segments with increasing TTL into the TCP connection.
Firewalls along the path are more likely to respond to packets
with an exceeded TTL if they are part of an established TCP connection.
While this technique may not always make it all the way to the client,
it tends to get close.

This Go package implements the 0trace traceroute technique.
The API is straightforward:
Instantiate a new `ZeroTrace` object by calling `NewZeroTrace`.
Then, start the object by invoking its `Start` method.
Afterwards, you can invoke the `CalcRTT` method
by providing the `net.Conn` object of an already-established TCP connection.
`CalcRTT` returns the round trip time to the client
(or the hop that's closest) as `time.Duration`, or an error.

## Configuration

ZeroTrace's
[constructor](https://pkg.go.dev/github.com/brave/zerotrace#NewZeroTrace)
expects a configuration object as argument.  Take a look at the
[`Config`](https://pkg.go.dev/github.com/brave/zerotrace#Config)
struct to learn more about configuration options.  The function
[`NewDefaultConfig`](https://pkg.go.dev/github.com/brave/zerotrace#NewDefaultConfig)
returns a default configuration object with reasonable defaults.

## Example

Use the code in the [example](example/) directory to get started.

## Development

To test and lint the code, run:

    make
