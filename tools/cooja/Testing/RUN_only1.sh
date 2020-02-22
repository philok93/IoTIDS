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
rm -f *.log *.cooja_log
rm -fr se obj_cooja
rm -f symbols.c symbols.h

# Compile COOJA
echo ">>>>>>> Building COOJA <<<<<<<<"
(cd $CONTIKI/tools/cooja && ant clean && ant jar)
if [ "$?" != "0" ]; then
  echo "Compilation of COOJA failed"
  exit 1
fi

TEST1=read_IDS_allnodes_sciptIDS2_clone_selfw
TEST2=read_IDS_allnodes_sciptIDS5_clone

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST1-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST1 RUN_REPEATED_LAST.log
  mv $TEST1.log clone_test/$TEST1-$COUNTER.log
done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST2-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST2 RUN_REPEATED_LAST.log
  mv $TEST2.log clone_test/$TEST2-$COUNTER.log
done



echo
cat RUN_REPEATED_LAST.log
echo
echo ">>>>>>> DONE! Test logs stored in $TEST1-[1-$REPEATS].log <<<<<<<<"
