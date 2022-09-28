<?php

/**
 * Return fake Java headers from a Jboss Wildfly.
 */
function fakeHttpJavaHeaders(){
    header("Server: WildFly/8",true);
    header("X-Powered-By: Undertow/1",true);
}

/**
 * Return the storage path.
 */
function getStoragePath($filename){

    $path = "./data/" . date('Y-m-d') . "/". $_SERVER['REMOTE_ADDR']. "/";

    if (!file_exists($path)) {
        // create directory
        mkdir($path, 0777, true);
    }
    return  $path . $filename;
}

/**
 * Save data in file.
 */
function saveFile($filename, $data){
      file_put_contents(getStoragePath($filename), $data);
}

/**
 * Decompile Java Class file
 */
function decompile($classFileName, $javaFileName){
    $classFilePath = getStoragePath($classFileName);
    $javaFilePath = getStoragePath($javaFileName);
    $command = "java -jar ./lib/cfr-0.152.jar $classFilePath > $javaFilePath";
    echo $command;
    exec($command);
}

/**
 * A Simple logger.
 */
function logAttack($log_msg, $isEnd = false) {

    $log_file_path = getStoragePath("attack.log");

    // write the content
    $data = "> " . $log_msg . "\n";
    file_put_contents($log_file_path, $data, FILE_APPEND);

    if($isEnd){
        file_put_contents($log_file_path,"---------------------------------------------------\n\n",FILE_APPEND);
    }
}

/**
 * Download a remote data.
 */
function downloadData($url, $logResponse = true){

    // Create curl resource.
    $ch = curl_init();

    // Set  tyarget url.
    curl_setopt($ch, CURLOPT_URL, $url);

    // Return the transfer as a string.
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

    // We wait maximum 20 sec.
    curl_setopt($ch,CURLOPT_TIMEOUT,20);

    // Download the infected payload from the hacker server.
    $data = curl_exec($ch);

    // Get Status Code.
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    // We save it for analysis.
    if ($logResponse){
        logAttack("PAYLOAD:$url ($http_code)\n" . $data);
    }

    // close curl resource to free up system resources.
    curl_close($ch);   
    
    return $data;
}

/**
 * Analyze the LDAP URL in the JNDI Request.
 */
function analyzeLdapUrl($payload){

    // Check for Basic64 Command.
    $pointer = strpos($payload, "//");

    // The JNDI contains a Basic64 command.
    if ($pointer == FALSE){
      logAttack("No LDAP URL found !");
      return false;
    }

    // Generate an unobfruscated LDAP URL
    $ldapurl = "ldap://" . substr($payload, $pointer + 2, -1);

    // Capture the remote payload
    $data = downloadData($ldapurl);
    analyzeLdapEntry($data);
}

/**
 * Analyze the LDAP Entry.
 */
function analyzeLdapEntry($entry){

    // We extract the LDAP Entry
    $lines = explode("\n", $entry);

    // Remove the first DN line
    array_shift($lines);

    // Remove empty lines
    $lines = array_filter($lines);

    $ldapEntry = [];

    // For each key / value lines
    foreach($lines as $line){
        $line = trim($line);
        list($key,$value) = explode(": ", $line);
        $ldapEntry[$key] = $value;
    }

    $codeFound = false;

    // The java code is serialized into the LDAP Entry
    if (array_key_exists("javaSerializedData",$ldapEntry)){

        // TODO : Check the safetyness of javaFactory value
        $classFileName = $ldapEntry['javaFactory'].".class";
        $javaFileName = $ldapEntry['javaFactory'].".java";

        logAttack("javaSerializedData Found : ". $classFileName);
        $data = $ldapEntry['javaSerializedData'];
        $codeFound = true;
    }

    // If we find a remote Java code base we download the class content
    else if (array_key_exists("javaCodeBase",$ldapEntry) && array_key_exists("javaFactory",$ldapEntry)){

        $classFileName = $ldapEntry['javaFactory'].".class";
        $javaFileName = $ldapEntry['javaFactory'].".java";

        $data = downloadData($ldapEntry['javaCodeBase']."/".  $classFileName, false);
        $codeFound = true;
    }

    // If a Java code is found, we save it and decompile it !
    if ($codeFound){
        logAttack("javaCodeBase Found : " .   $classFileName);
        saveFile( $classFileName, $data);
        decompile($classFileName,$javaFileName);
    }
}

/**
 * Analyze the Base64 shell command.
 */
function analyzeBase64Command($payload){

    // Check for Basic64 Command.
    $pointer = strpos($payload, "Base64");

    // The JNDI contains a Basic64 command.
    if ($pointer == FALSE){
      logAttack("No base64 shell code found !");
      return false;
    }

    // We extract the base64 encoded command.
    $basic64 = substr($payload, $pointer + 7, -1);

    // We decode the shell command and log it.
    $command = base64_decode($basic64);

    // We split the shell command into unique instructions for analysis.
    $command = str_replace(array("(",")"), "",  $command);
    $command = str_replace(array("||"), "|",  $command);
    $instructions = explode('|',$command);

    // We check each instruction to detect if it's a curl or wget command.
    foreach($instructions as $instruction){

      // If it's a curl or wget command.
      if (strpos($instruction,"curl") !== FALSE || strpos($instruction,"wget") !== FALSE){

          // We extract all args of the shell instruction.
          $args = explode(" ", $instruction);

          // The URL is the last arg of the string.
          $url = end($args);

          // We log the remote payload.
          downloadData($url);
      }
  }
}

/**
 * Analyze the request and return true if an attack is detected.
 */
function analyzeRequest($data){

    $isAttack = false;

    // We try to find a dollar in the different values that can be a proof of log4shell attack.
    foreach ( $data as $key => $value) {

        // We found a dollar in a HTTP header or Request.
        if (strpos($value, '$')  !== FALSE) {
            $isAttack = true;

            logAttack($key . ":" .  print_r($value,true));
        
            // Analyze the LDAP URL Content
            analyzeLdapUrl($value);
            
            // Analyze the Shell command
            analyzeBase64Command($value);
        }
    }

    if ($isAttack){
        logAttack("Finished !",true);
    }

    return $isAttack;
}
