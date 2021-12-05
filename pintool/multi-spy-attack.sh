#!/bin/bash
i=0
multi_spy_keys="multi_spy_keys.txt"
rm $multi_spy_keys

while [ $i -le $1 ]
do

$PIN_ROOT/pin -ifeellucky -t obj-intel64/pin_sharp_cache.so $2 $3 4980  $i -- ./rsa | grep "Combined Key" > temp.txt

cat temp.txt

cat $multi_spy_keys temp.txt > temp1.txt
mv temp1.txt $multi_spy_keys

python3 process-multi-spy-attack.py -f $multi_spy_keys -i $i

#rm temp1.txt
#rm temp.txt
i=$((i+1))
done
