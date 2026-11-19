#!/bin/bash
# make -j4 of 24 C files with gcc, then run the program.
set -euo pipefail; shopt -s inherit_errexit
mkdir -p p; cd p
for i in $(seq 1 24); do printf 'int f%d(int x){int s=0;for(int i=0;i<x;i++)s+=i*%d;return s;}\n' $i $i > f$i.c; done
{ echo '#include <stdio.h>'; for i in $(seq 1 24); do echo "int f$i(int);"; done
  echo 'int main(void){long t=0;'; for i in $(seq 1 24); do echo "t+=f$i(100);"; done; echo 'printf("%ld\n",t);return 0;}'; } > main.c
objs=$(for i in $(seq 1 24); do printf 'f%d.o ' $i; done)
printf 'prog: main.o %s\n\tgcc -o $@ $^\n%%.o: %%.c\n\tgcc -O2 -c $< -o $@\n' "$objs" > Makefile
make -s -j4
./prog
