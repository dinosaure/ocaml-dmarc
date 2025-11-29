# OCaml implementation of DMARC

A little library to verify incoming emails according DMARC policy. We can
analyze also `Authentication-Results` and generate this field for an email. We
don't **filter** emails according a DMARC policy nor be able to respond a DMARC
report as a DMARC service should. The purpose of this library is primarily to
analyze emails and generate an Authentication-Results field for an SMTP server.
