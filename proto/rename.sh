#!/bin/bash

cd $1 && for fname in ./*$2; do mv ${fname} $(basename ${fname} $2)$3; done