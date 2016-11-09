#!/bin/bash

################################### Coelioxys #####################################
#### Copyright (C) 2016 Fernando Vañó García					  #
####										  #
####    This program is free software: you can redistribute it and/or modify	  #
####    it under the terms of the GNU Affero General Public License as		  #
####    published by the Free Software Foundation, either version 3 of the	  #
####    License, or (at your option) any later version.				  #
####										  #
####    This program is distributed in the hope that it will be useful,		  #
####    but WITHOUT ANY WARRANTY; without even the implied warranty of		  #
####    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the		  #
####    GNU Affero General Public License for more details.			  #
####										  #
####    You should have received a copy of the GNU Affero General Public License  #
####    along with this program.  If not, see <http://www.gnu.org/licenses/>.	  #
####										  #
####	Fernando Vañó García <fernando@fervagar.com>		                  #
####										  #
###################################################################################


if [ $# -eq 0 ]; then
	echo "1 Argument is needed (name of the asm source code file)"
else
	EXT="${1##*.}"
	if [ $EXT == "s" ]; then
		FILENAME=${1%.*}
	else
		FILENAME=$1
	fi
	as -gstabs $FILENAME.s -o $FILENAME.o
	if [ $? -eq 0 ]; then
		ld $FILENAME.o -o infector;
		rm $FILENAME.o
	fi
fi
