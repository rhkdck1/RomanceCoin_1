#!/usr/bin/env bash

export LC_ALL=C
TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
BUILDDIR=${BUILDDIR:-$TOPDIR}

BINDIR=${BINDIR:-$BUILDDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

MICROD=${MICROD:-$BINDIR/romanced}
MICROCLI=${MICROCLI:-$BINDIR/romance-cli}
MICROTX=${MICROTX:-$BINDIR/romance-tx}
MICROQT=${MICROQT:-$BINDIR/qt/romance-qt}

[ ! -x $MICROD ] && echo "$MICROD not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
MBCVER=($($MICROCLI --version | head -n1 | awk -F'[ -]' '{ print $6, $7 }'))

# Create a footer file with copyright content.
# This gets autodetected fine for romanced if --version-string is not set,
# but has different outcomes for romance-qt and romance-cli.
echo "[COPYRIGHT]" > footer.h2m
$MICROD --version | sed -n '1!p' >> footer.h2m

for cmd in $MICROD $MICROCLI $MICROTX $MICROQT; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=${MBCVER[0]} --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-${MBCVER[1]}//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
