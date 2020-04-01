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

TEST1=read_IDS_allnodes_sciptIDS5_clone
TEST2=read_IDS_allnodes_sciptIDS1-clone
#TEST3=read_IDS_allnodes_sciptIDS2-clone
# TEST4=read_IDS_allnodes_sciptIDS4-clone
# TEST5=read_IDS_allnodes_sciptIDS5_clone
# TEST6=read_IDS_allnodes_sciptIDS6-clone
# TEST7=read_IDS_allnodes_sciptIDS7-clone
# TEST8=read_IDS_allnodes_sciptIDS8-clone
# TEST9=read_IDS_allnodes_sciptIDS9-clone
# TEST10=read_IDS_allnodes_sciptIDS10-clone


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

# for COUNTER in `seq 1 $REPEATS`;
# do
#   echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST4-$COUNTER.log <<<<<<<<"
#   bash RUN_TEST.sh $TEST4 RUN_REPEATED_LAST.log
#   mv $TEST4.log clone_test/$TEST4-$COUNTER.log
# done

# for COUNTER in `seq 1 $REPEATS`;
# do
#   echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST5-$COUNTER.log <<<<<<<<"
#   bash RUN_TEST.sh $TEST5 RUN_REPEATED_LAST.log
#   mv $TEST5.log clone_test/$TEST5-$COUNTER.log
# done

# for COUNTER in `seq 1 $REPEATS`;
# do
#   echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST6-$COUNTER.log <<<<<<<<"
#   bash RUN_TEST.sh $TEST6 RUN_REPEATED_LAST.log
#   mv $TEST6.log clone_test/$TEST6-$COUNTER.log
# done

# for COUNTER in `seq 1 $REPEATS`;
# do
#   echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST7-$COUNTER.log <<<<<<<<"
#   bash RUN_TEST.sh $TEST7 RUN_REPEATED_LAST.log
#   mv $TEST7.log clone_test/$TEST7-$COUNTER.log
# done


# for COUNTER in `seq 1 $REPEATS`;
# do
#   echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST8-$COUNTER.log <<<<<<<<"
#   bash RUN_TEST.sh $TEST8 RUN_REPEATED_LAST.log
#   mv $TEST8.log clone_test/$TEST8-$COUNTER.log
# done


# for COUNTER in `seq 1 $REPEATS`;
# do
#   echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST9-$COUNTER.log <<<<<<<<"
#   bash RUN_TEST.sh $TEST9 RUN_REPEATED_LAST.log
#   mv $TEST9.log clone_test/$TEST9-$COUNTER.log
# done

# for COUNTER in `seq 1 $REPEATS`;
# do
#   echo ">>>>>>> Test $COUNTER/$REPEATS: $TEST10-$COUNTER.log <<<<<<<<"
#   bash RUN_TEST.sh $TEST10 RUN_REPEATED_LAST.log
#   mv $TEST10.log clone_test/$TEST10-$COUNTER.log
# done


echo
cat RUN_REPEATED_LAST.log
echo
echo ">>>>>>> DONE! Test logs stored in $TEST1-[1-$REPEATS].log <<<<<<<<"
