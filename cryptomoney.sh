#!/bin/bash

# the first command-line parameter is in $1, the second in $2, etc.

case "$1" in

    name) echo "CryptoDollar"
	  # additional parameters provided: (none)
	  ;;

    genesis) java Crypto.java genesis block_0.txt
	     # additional parameters provided: (none)
             ;;

    generate) java Crypto.java generate $2
	      # additional parameters provided: the wallet file name
              ;;

    address) java Crypto.java address $2
	     # additional parameters provided: the file name of the wallet
	     ;;

    fund) java Crypto.java fund $2 $3 $4
	  # additional parameters provided: destination wallet
	  # address, the amount, and the transaction file name
          ;;

    transfer) java Crypto.java transfer $2 $3 $4 $5
	      # additional parameters provided: source wallet file
	      # name, destination address, amount, and the transaction
	      # file name
	      ;;

    balance) java Crypto.java balance $2
	     # additional parameters provided: wallet address
	     ;;

    verify) java Crypto.java verify $2 $3
	    # additional parameters provided: wallet file name,
	    # transaction file name
	    ;;

    mine) java Crypto.java mine $2
		 # additional parameters provided: difficulty
		 ;;
    
    validate) java Crypto.java validate
	      # additional parameters provided: (none)
	      ;;

    *) echo Unknown function: $1
       ;;

esac
