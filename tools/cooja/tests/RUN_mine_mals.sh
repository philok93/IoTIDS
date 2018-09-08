#!/bin/bash

# Usage
#RUNS 1 MLAICIOUS AND 3 NORMAL NODES
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

TEST11=testwith4fixed1mals
TEST2=testwith4fixed2mals
TEST3=testwith4fixed3mals
TEST4=testwith4fixed4mals
TEST5=testwith4fixed5mals
TEST6=testwith4fixed6mals


# Run tests
for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST11-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST11 RUN_REPEATED_LAST.log
  mv $TEST11.log $TEST11-1$COUNTER.log
done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST2-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST2 RUN_REPEATED_LAST.log
  mv $TEST2.log $TEST2-1$COUNTER.log
done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST2-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST3 RUN_REPEATED_LAST.log
  mv $TEST3.log $TEST3-1$COUNTER.log
done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST2-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST4 RUN_REPEATED_LAST.log
  mv $TEST4.log $TEST4-1$COUNTER.log
done


for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST2-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST5 RUN_REPEATED_LAST.log
  mv $TEST5.log $TEST5-1$COUNTER.log
done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST2-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST6 RUN_REPEATED_LAST.log
  mv $TEST6.log $TEST6-1$COUNTER.log
done



echo
cat RUN_REPEATED_LAST.log
echo
echo ">>>>>>> DONE! Test logs stored in $TEST-[1-$REPEATS].log <<<<<<<<"
