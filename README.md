# img4

Image4 dumper tool.

## Requirements

- `asn1crypto`
- `pylzfse` (bundled in `./ext/pylzfse`)
- Using `git clone --recursive`

## Usage

```
usage: img4.py [-h] [-r] infile [outfile]

positional arguments:
  infile      input .img4/.im4m/.im4p file
  outfile     output data file for payload

optional arguments:
  -h, --help  show this help message and exit
  -r, --raw   print raw parsed data
```

# dt

Apple device tree dumper tool.

## Usage

```
usage: dt.py infile

positional arguments:
  infile      input device tree file
```

# macho

Mach-O dumper tool.

## Usage

```
usage: macho.py infile

positional arguments:
  infile      input device tree file
```

# License

See `LICENSE.md`.
