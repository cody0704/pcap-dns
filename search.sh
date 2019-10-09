#!/bin/bash

user="root"
pass="toor"
database="pcap"
table="dns"
 
title="[pcap search]"
echo "$title"

Search(){
    sql="SELECT COUNT(*) FROM $1;"
    mysql="mysql -u "$user" -p"$pass" --protocol=tcp "$database""

    result="$($mysql -e "$sql")"
    count=`echo "$result" | sed '1d' `
    if [ $count -ne 0 ]; then
        if [ `echo "$count%50" | bc ` -eq 0 ] ;then
            totalPage=`echo "$count"/50 | bc`
        else
            totalPage=`echo "$count"/50 + 1 | bc`
        fi

        select page in `seq 1 $totalPage` "Quit"; do
            case "$REPLY" in
                * ) 
                    if [[ $REPLY == *[0-9]* ]]; then
                        if [ `echo "$REPLY <= $totalPage" | bc` -eq 1 ]; then
                            no=`echo "($REPLY-1)*50" | bc`
                            sql="SELECT Date,Time,usec,SourceIP,SourcePort,DestinationIP,DestinationPort,FQDN FROM $1 Limit $no, 50;"
                            data="$($mysql -e "$sql")"
                            echo "$data"
                            echo "Page：$page/$totalPage"
                        else
                            if [ "$(($totalPage+1))" == "$REPLY" ]; then
                                echo "quit search!"
                                break
                            fi
                            echo "No such page."
                        fi
                    else
                        echo "Please enter option number."
                    fi
                ;;
            esac
        done
    else
        echo "Not found data."
    fi

    clear;
}

options=("Use SourceIP" "Use Time range" "Use FQDN")

select opt in "${options[@]}" "Quit"; do 
    case "$REPLY" in

    1 ) 
        read -p "Please input [SourceIP]: " srcIP
        sql="dns WHERE SourceIP=\""$srcIP\"""
        Search "$sql" ;;
    2 ) 
        read -p "Please input [StartDate] [StartTime] [EndDate] [EndTime]: " startDate startTime endDate endTime
        sql="(SELECT *,concat(Date,\" \",Time) as timestamp FROM dns WHERE 1) as table2 WHERE timestamp BETWEEN \"$startDate $startTime\" AND \"$endDate $endTime\""
        Search "$sql" ;;
    3 ) 
        read -p "Please input [FQDN]: " FQDN
        sql="dns WHERE FQDN=\""$FQDN\"""
        Search "$sql" ;;

    $(( ${#options[@]}+1 )) ) echo "Goodbye!"; break;;
    *) echo "Invalid option.";continue;;

    esac

done