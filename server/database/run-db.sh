sudo docker run --name novpn-db -e MYSQL_ROOT_PASSWORD=secretpassword --volumes-from novpn_db -d -p 3306:3306 mysql