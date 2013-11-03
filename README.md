ausec
=====
_Au secours!_ my server has been compromised.

**ausec** is a small utility that intends to easily find files that have been compromised.

It computes a keyed-hmac of a file's content and/or attributes (e.g. xattr, ACL). The keyed-hmac value is stored using the filesystem's extended attributes, or compared to the previously stored value to detect any changes.

It is still in development, so don't use it! Any comment, bug reports or patches are welcome. :)

---
## FAQ ##

---
## TODO-list ##
* configuration file
* structured data encoding (xattr, ACL, stat)
