# Encrypted evidence images

The CLI accepts `--password-file PATH` or `--password-stdin` with `--image` for
image-container encryption supported by `exhume_body`. With no explicit source,
an interactive terminal prompts without echoing the password. Account commands
and folder analysis do not request an image password.

Credentials are read once and retained in host memory. The CLI authenticates the
image before creating or opening the case database. Evidence tools reuse the
credentials when reopening the selected image; they never request passwords from
the model or write them into case records.

Embedding applications pass `Arc<BodyOpenOptions>` through the
`ExhumeAgent::with_body_open_options` builder. Directly constructed evidence tools
provide the same builder. Custom `AgentToolProvider` implementations receive
`context.body_open_options`; keep this host-only value out of model inputs.
The existing constructors use no container credentials.

The evidence I/O helpers expose `open_filesystem_with_options` and
`extract_file_bytes_with_options`. Their existing counterparts remain available
for unencrypted images. Container passwords are independent of BitLocker FVEKs
and other encryption inside the acquired disk.
