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
usage: dt.py [-h] {dump,find,to-fdt,to-adt,to-src,diff,regs} ...

process Apple (ADT) and Flattened (FDT) device tree files

positional arguments:
  {dump,find,to-fdt,to-adt,to-src,diff,regs}
                        subcommand
    dump                visually show device tree
    find                find node in device tree
    to-fdt              convert to flattened device tree
    to-adt              convert to Apple device tree
    to-src              convert to device tree source
    diff                visually show the difference between two device trees
    regs                show calculated register ranges for given path

optional arguments:
  -h, --help            show this help message and exit
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
