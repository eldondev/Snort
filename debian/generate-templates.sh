#!/bin/sh -e

# Generate templates for the Snort packages
# This should be done whenever the templates are modified

for package in "" mysql pgsql inline; do
    packagename=$package
    [ -n "$package" ] && packagename="-$packagename"
    OUTPUT="snort$packagename.templates"
    echo "Generating templates for snort$packagename at $OUTPUT"
    cat snort.TEMPLATE.templates | sed -e "s/{PACKAGE}/$packagename/g" >$OUTPUT
    # Add Database templates also
    if [ "$package" = "mysql" ] || [ "$package" = "pgsql" ] ; then
        cat snort.DATABASE.templates | sed -e "s/{PACKAGE}/$packagename/g" | sed -e "s/{DATABASE}/$package/g" >>$OUTPUT
    fi
            
    # Finally, add any additional templates this package might have
    if [ -e "snort$packagename.ADD.templates" ] ; then
        cat "snort$packagename.ADD.templates"  >>$OUTPUT
    fi
done

exit 0
