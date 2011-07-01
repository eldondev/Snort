#!/usr/bin/perl
#
# Give a rules file, remove all alerts which are not GPL. Based on 
# Sourcefire's VRT Certified Rules License Agreement 
# (http://www.snort.org/about_snort/licenses/vrt_license.html)
# this means that the rule's sid must be outside the 3,465 - 1,000,000 range
#
# This program is copyright 2007 by Javier Fernandez-Sanguino <jfs@debian.org>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# For more information please see
#  http://www.gnu.org/licenses/licenses.html#GPL
#

while (<STDIN>) {
    if ( ! /^alert/ ) {
        print ;
    } elsif ( /sid:(\d+)[^\d]/ ) {
        print if ( $1 < 3465 || $1 > 1000000 );
    } else {
        print "WARN: Alert without sid, will not print\n";
    }
}

