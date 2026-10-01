# Vendor policy

`vendor/arti` is supplied upstream Arti 0.46.0 source. The ZTSEC relay implementation does not modify any file under `vendor/arti`.

Release ZIPs omit the unchanged `vendor/` tree. If a future engineering change genuinely modifies an upstream vendor file, that modified vendor content must be included in that specific release archive and called out explicitly in the completion report.
