# ProtocolEncoding

The `ProtocolEncoding` is an inherent part of lib.
Whenever you touch a file related to `ProtocolEncoding` you should ensure
that you use this skill.

## Backward compatibility

One of the hardest things about ProtocolEncoding is that backward compatibility is
a hard requirement. You MUST ensure that all your changes are backwards compatible

## Avoiding panics

This code MUST never panic.
Overflows, underflows, out-of-bounds, ... You must handle it.

Be careful, a malicious attacker can just send whatever bytes they like.
Don't trust the byte stream on deserialization.

## Encoding lengths

You should encode lengths as compact size integer.

## Avoiding DoS

When decoding we sometimes encode length fields and allocate an array.
Make sure you don't over-allocate if the number is too big.
An attacker can use this as a DoS vector
