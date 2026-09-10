<?php
// Static tests: sample contents are never evaluated or included.
// Optional argument: an inert site fixture with wp-content/object-cache.php,
// mu-plugins/ridge-interface-bit.php and e0539fae.zip from the reviewed samples.
$repo = dirname(__DIR__, 2);
$source = file_get_contents($repo . '/scanner/wp-warden-pef.php');
foreach (['prepare_php_pattern_rule','scan_fast_trusted_family_rules','sc_onyx_payload_matches',
    'sc_onyx_file_matches','sc_onyx_zip_matches','sc_onyx_related_markers',
    'scan_large_php_prefix_safely','is_php_like_extension','audit_sc_onyx_persistence',
    'find_sc_onyx_tagged_php_carriers','normalize_path','normalize_relative'] as $name) {
    if (!preg_match('/^function ' . $name . '\b[\s\S]*?(?=^function |\z)/m', $source, $m)) throw new RuntimeException($name);
    eval($m[0]); // Trusted scanner definitions only.
}
function warden_preg_match($p,$s,&$m=null,$f=0,$o=0,$context=[]) {
    $result = preg_match($p,$s,$m,$f,$o);
    if ($result === false) throw new RuntimeException(preg_last_error_msg());
    return $result;
}
function add_finding($finding,$unused=false) { $GLOBALS['hits'][] = $finding; }
function say($text,$unused=false) { $GLOBALS['messages'][]=$text; }
function check($condition,$label) { if (!$condition) throw new RuntimeException($label); echo "PASS $label\n"; }
ini_set('pcre.backtrack_limit','500000');
$rules=[];
foreach(json_decode(file_get_contents($repo.'/intel/patterns/php-malware-rules.json'),true)['rules'] as $rule) {
    if (in_array($rule['id'],['PHP_SC_OBFUSCATED_CORE_001','PHP_SC_OBJECT_CACHE_RESTORER_001'],true)) $rules[]=prepare_php_pattern_rule($rule);
}
$intel=['php_rules'=>$rules];
$temp=tempnam(sys_get_temp_dir(),'warden-ridge-'); unlink($temp); mkdir($temp);
$core='<?php /* SCV:4.5.3 */ $a="SC_CORE_BOOT_VER sc_boot_ver array_merge strpos";';
$loader='<?php /* .wp-object-cache-0f344484 */ /* SCOCV:4.5.3 */ $a="__scf_ _sc_fpc /mu-plugins /.sd_ridge-interface-bit";';
try {
    $content=$temp.'/wp-content'; mkdir($content); mkdir($content.'/mu-plugins');
    file_put_contents($content.'/object-cache.php',$loader);
    file_put_contents($content.'/mu-plugins/renamed.php',$core);
    file_put_contents($content.'/.sd_ridge-interface-bit','4.5.3');
    file_put_contents($content.'/.pv_ridge-interface-bit','123:456:'.str_repeat('a',32));
    file_put_contents($content.'/.sd_unrelated','4.5.3');
    check(sc_onyx_payload_matches($core),'slug-independent core');
    check(sc_onyx_payload_matches($loader),'object-cache restorer');
    foreach (['<?php /* ordinary object cache */','<?php /* SCOCV:4.5.3 */',
        str_replace('_sc_fpc','ordinary',$loader), '4.5.3', 'ridge-interface-bit'] as $benign) {
        check(!sc_onyx_payload_matches($benign),'negative payload fixture');
    }
    check(sc_onyx_related_markers($content,[])===[],'standalone state is not malware');
    check(count(sc_onyx_related_markers($content,[$content.'/object-cache.php']))===2,'only confirmed-slug state is associated');
    foreach ([$core,$loader] as $index=>$data) {
        $path=$content.'/padded'.$index.'.php';
        file_put_contents($path,$data."\n/*".str_repeat('a',7*1024*1024).'*/');
        $hits=[]; scan_large_php_prefix_safely($path,'renamed.php',[]);
        check(count($hits)===1,'padded family prefix '.$index);
    }
    // Test the actual coordinated report-only audit, including extensionless state.
    $apply=false; $cleanupScOnyxAuto=false; $quarantineDir=null;
    $state=['sc_onyx_cleanup'=>['detected'=>0]]; $hits=[]; $messages=[];
    audit_sc_onyx_persistence($temp);
    check(count(array_filter($hits,static function($f){return $f['type']==='sc_onyx_persistence';}))===2,'audit detects loader and renamed MU core');
    check(count(array_filter($hits,static function($f){return $f['type']==='sc_onyx_related_state';}))===2,'audit reports both state files');
    check(is_file($content.'/object-cache.php'),'report-only preserves files');
    if (class_exists('ZipArchive')) {
        foreach (['renamed.zip'=>$core,'benign.zip'=>'<?php // ordinary plugin'] as $name=>$data) {
            $zip=new ZipArchive(); $zip->open($content.'/'.$name,ZipArchive::CREATE);
            $zip->addFromString('arbitrary-name/plugin.php',$data); $zip->close();
            check(sc_onyx_zip_matches($content.'/'.$name)===($name==='renamed.zip'),'archive '.$name);
        }
    } else {
        file_put_contents($content.'/unreadable.zip','not an archive');
        $messages=[]; audit_sc_onyx_persistence($temp);
        check(count(array_filter($messages,static function($m){return strpos($m,'ZIP extension')!==false;}))===1,'missing ZIP support is disclosed');
    }
    if (isset($argv[1])) {
        $real=realpath($argv[1]); check($real!==false,'sample directory exists');
        foreach (['object-cache.php'=>'PHP_SC_OBJECT_CACHE_RESTORER_001','mu-plugins/ridge-interface-bit.php'=>'PHP_SC_OBFUSCATED_CORE_001'] as $name=>$id) {
            $path=$real.'/wp-content/'.$name; $data=file_get_contents($path);
            $hits=[];scan_fast_trusted_family_rules($path,$name,[],$rules,$data);
            check(in_array($id,array_column($hits,'rule_id'),true),'real sample rule '.$name);
            check(sc_onyx_file_matches($path),'real sample coordinated '.$name);
            $hits=[];scan_large_php_prefix_safely($path,$name,[]);
            check(in_array($id,array_column($hits,'rule_id'),true),'real sample prefix '.$name);
        }
        if(class_exists('ZipArchive')) check(sc_onyx_zip_matches($real.'/wp-content/e0539fae.zip'),'real archive');
    }
} finally {
    // Only remove files created inside this test's unique temporary directory.
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temp,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($it as $file) { if($file->isDir()&&!$file->isLink()) rmdir($file->getPathname()); else unlink($file->getPathname()); }
    rmdir($temp);
}
