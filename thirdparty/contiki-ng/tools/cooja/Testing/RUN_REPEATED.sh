#!/bin/bash

# Usage
if [ $# -eq 2 ]; then
  REPEATS=$1
  TEST=$2
else
  echo "Usage: $0 <nr_repeats> <test>"
  echo "Example: $0 10 cooja_helloworld"
  exit 1
fi

# Locate Contiki/COOJA
if [ -z "$CONTIKI" ]; then
  if [ -z "$CONTIKI_HOME" ]; then
  	CONTIKI_HOME=../../..
  fi
  CONTIKI=$CONTIKI_HOME
fi

# Clean up
rm -f *.cooja_log
rm -fr se obj_cooja
rm -f symbols.c symbols.h

# Compile COOJA
echo ">>>>>>> Building COOJA <<<<<<<<"
(cd $CONTIKI/tools/cooja && ant clean && ant jar)
if [ "$?" != "0" ]; then
  echo "Compilation of COOJA failed"
  exit 1
fi

# Run tests
for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST RUN_REPEATED_LAST.log
  mv $TEST.log $TEST-$COUNTER.log
done

echo
cat RUN_REPEATED_LAST.log
echo
echo ">>>>>>> DONE! Test logs stored in $TEST-[1-$REPEATS].log <<<<<<<<"
