#!/bin/sh
# Purges non-GPL rules from a common set

if [ -z "$1" ] ; then
    echo "Usage: $0 directory_with_rules"
fi

if [ ! -d "$1" ] ; then
    echo "ERROR: $1 is not a directory"
    exit 1
fi

for file in $1/*rules; do 
    if [ -r "$file" ] ; then
        name=`basename $file`
        if [ ! -e "$name" ] ; then
            cat $file |perl remove-non-gpl.pl >$name
        else
            echo "ERROR: Cowardly refusing to overwrite $name"
        fi
    fi
done

