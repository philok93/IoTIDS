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

TEST11=testnew5_cmd
WW=testNwithout_cmd
TEST2=testnew5_3norm_cmd
TEST3=testnew5_4norm_cmd
TEST4=testnew5_5norm_cmd
TEST5=testnew5_6norm_cmd
TEST6=testnew5_7norm_cmd
WTEST1=testNwithout_2norm_cmd
WTEST2=testNwithout_4norm_cmd
WTEST3=testNwithout_5norm_cmd
WTEST4=testNwithout_6norm_cmd
WTEST5=testNwithout_7norm_cmd
WTEST6=testNwithout_8norm_cmd


#Run tests
for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST2-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST2 RUN_REPEATED_LAST.log 
  mv $TEST2.log $TEST2-$COUNTER.log

done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST11-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST11 RUN_REPEATED_LAST.log
  mv $TEST11.log $TEST11-$COUNTER.log
done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST3-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST3 RUN_REPEATED_LAST.log
  mv $TEST3.log $TEST3-$COUNTER.log
done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST4-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST4 RUN_REPEATED_LAST.log
  mv $TEST4.log $TEST4-$COUNTER.log
done


for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST5-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST5 RUN_REPEATED_LAST.log
  mv $TEST5.log $TEST5-$COUNTER.log
done

for COUNTER in `seq 1 $REPEATS`;
do
  echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST6-$COUNTER.log <<<<<<<<"
  bash RUN_TEST.sh $TEST6 RUN_REPEATED_LAST.log
  mv $TEST6.log $TEST6-$COUNTER.log
done



echo
cat RUN_REPEATED_LAST.log
echo
echo ">>>>>>> DONE! Test logs stored in $TEST-[1-$REPEATS].log <<<<<<<<"
