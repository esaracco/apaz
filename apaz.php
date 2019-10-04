<?php
/*
 * Copyright (C) 2006
 * Emmanuel Saracco <esaracco@users.labs.libre-entreprise.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

  define ('APP_VERSION', '0.1.1cvs2006092600');

  /* Enable/Disable encryption of page links (so Web server logs 
   * could not/could be used to spy your web targets). */
  define ('A_CRYPT_ENABLED', 1); 
  /* Default URL to display */
  define ('A_DEFAULT_URL', 'http://www.gnu.org');

  /* Sockets connection timeout */
  define ('A_CONNECTION_TIMEOUT', 30);
  /* Prefix used to identified encrypted items */
  define ('A_CRYPTED_PREFIX', 'aPAzEU');
  /* Prefix used to identified serialized items */
  define ('A_SERIALIZED_PREFIX', 'aPAzSU');

  /* Main configuration array */
  $config = array ();

  $config['HTTPCodes'] = array (
    '401' => "You need authorization to access this URL",
    '403' => "Your don't have permission to acces this URL",
    '404' => "The page could not be found"
  );

  class APAz
  {
    var $_config = array ();
    var $vars = array (); // Internal variables
    var $formVars = array (); // Submitted pages variables (from form page)
    var $_fileInfos = array ();
    var $_socket = 0;
    var $_errno = 0;
    var $_errstr = '';
    var $_errurl = '';
    var $_isSubmit = false;
    var $_mainContent = '';
    var $_endTags = '';
    var $_previousKeyEU = '';
    var $_currentKeyEU = '';
    var $_scriptServer = '';
    var $_mainServer = '';
    var $_basePath = '';
    var $_firstTime = 0;
  
    function APAz ($config)
    {
      $this->_config = $config;

      /* Crypto is based on a new salt at every new loaded page, so it wont
       * be easy to decrypt Web server logs lines. */
      if (A_CRYPT_ENABLED)
      {
        /* Get previous EU key (to unencrypt) */
        $this->_previousKeyEU = $this->getCookie ('keyEU');
        /* Set next EU key (to encrypt) */
        if ($_SERVER['REQUEST_METHOD'] == 'POST')
        {
          $this->_currentKeyEU = $this->getUniqId ();
          $this->setCookie ('keyEU', $this->_currentKeyEU);
        }
        else
          $this->_currentKeyEU = $this->_previousKeyEU;
      }

      $this->getHTTPValues ();

      if ($this->isSubmit ())
      {
        $this->init ();
        $this->process ();
      }
      else
        $this->initFirst ();
    }

    function getHTTPValues ()
    {
      foreach (array (
        'apazBoxState' => 'visible',
        'apazFrame' => 0,
        'apazHistory' => '',
        'apazUseHistory' => 0,
        'apazHistoryIndex' => 0,
        'apazFormMethod' => '',
        'apazRawURL' => '',
        'apazMainURL' => '',
        'apazScriptURL' => '',
        'apazCurrentURL' => '',
        'apazBasePath' => ''
      ) as $k => $v)
        $this->vars[$k] = $this->getHTTPVar ($k, $v);

      /* Get submitted form variables if a form was submitted */
      if ($this->vars['apazFormMethod'])
      {
        $this->vars['apazFormMethod'] = 
          strtolower ($this->vars['apazFormMethod']);

        foreach ($_POST as $k => $v)
          if (!ereg ('^apaz', $k))
            $this->formVars[$k] = $v;
      }

      $this->unserializeValues ();

      if (A_CRYPT_ENABLED)
        $this->unencryptValues ();

      if ($_SERVER['REQUEST_METHOD'] == 'POST')
      {
        $this->vars['incrustation'] = 1;

        if ($this->vars['apazUseHistory'])
          $this->useHistory ($this->vars['apazHistoryIndex']);
      }
    }

    function setApazCurrentURL ()
    {
      if (empty ($this->vars['apazCurrentURL']))
        $this->vars['apazCurrentURL'] = $this->vars['apazMainURL'];
  
      if (!preg_match ('/^\s*(http|ftp)/', $this->vars['apazCurrentURL']))
      {
        if (
            !empty ($this->vars['initBasePath']) && 
            $this->vars['apazCurrentURL']{0} != '/')
          $this->vars['apazCurrentURL'] = 
            $this->vars['initBasePath'] . '/' . $this->vars['apazCurrentURL'];

        if (isset ($this->vars['apazMainURLStruct']['scheme']))
          $this->vars['apazCurrentURL'] = 
            $this->vars['apazMainURLStruct']['scheme'] . '://' . 
            $this->vars['apazMainURLStruct']['host'] . ':' . 
            $this->vars['apazMainURLStruct']['port'] . '/' . 
              $this->vars['apazCurrentURL'];
      }

      if (!($this->vars['apazCurrentURLStruct'] = 
        @parse_url ($this->vars['apazCurrentURL'])))
      {
        $this->_errno = 1;
        $this->_errstr = "An error occured while parsing the URL";
        return false;
      }

      /* We changing of main host */
      if (preg_match ('/^\s*(http|ftp)/', $this->vars['apazCurrentURL']) &&
        $this->vars['apazCurrentURLStruct']['host'] != 
          $this->vars['apazMainURLStruct']['host'])
      {
        $this->vars['apazMainURL'] = $this->vars['apazCurrentURL'];
        $this->vars['apazMainURLStruct'] = $this->vars['apazCurrentURLStruct'];
        $this->normalizeMainURL ();
        $this->normalizeCurrentURL ();
      }

      $this->normalizeCurrentURL ();

      /* Relative to absolute URL */
      $this->vars['apazCurrentURLStruct']['path'] = 
        $this->getAbsoluteURL ($this->vars['apazCurrentURLStruct']['path'], 
        $this->vars['initBasePath']);

      return true;
    }

    function setApazMainURL ()
    {
      if (!($this->vars['apazMainURLStruct'] = 
        @parse_url ($this->vars['apazMainURL'])))
      {
        $this->_errno = 1;
        $this->_errstr = "An error occured while parsing the URL";
        return false;
      }
      $this->normalizeMainURL ();

      return true;
    }

    function setApazScriptURL ()
    {
      $this->vars['apazScriptURL'] = 
        (isset ($_SERVER['HTTPS']) ? 'https' : 'http') . '://' .
        $_SERVER['HTTP_HOST'] . ':' . 
        $_SERVER['SERVER_PORT'] . $_SERVER['PHP_SELF'];
      if (!($this->vars['apazScriptURLStruct'] = 
        @parse_url ($this->vars['apazScriptURL'])))
      {
        $this->_errno = 1;
        $this->_errstr = 
          "An error occured while parsing the URL application script";
        return false;
      }
      $this->normalizeScriptURL ();

      return true;
    }

    function initFirst ()
    {
      $this->_firstTime = 1;
      $this->setApazScriptURL ();
      $this->vars['apazHistory'] = '';
      $this->vars['apazMainURL'] = A_DEFAULT_URL;
      $this->vars['apazCurrentURL'] = A_DEFAULT_URL;
      $this->_mainContent = $this->getDefaultPageHTML ();
    }

    function isSerialized ($value)
    {
      return (ereg ('^' . A_SERIALIZED_PREFIX, $value));
    }

    function isEncrypted ($value)
    {
      return (ereg ('^' . A_CRYPTED_PREFIX, $value));
    }

    function unserializeValues ()
    {
      foreach (array (
        'apazHistory') as $name)
        if ($this->isSerialized (@$this->vars[$name]))
          $this->vars[$name] = $this->getUnserializedValue ($this->vars[$name]);
    }

    function unencryptValues ()
    {
      foreach (array (
        'apazRawURL', 
        'apazCurrentURL') as $name)
        if ($this->isEncrypted ($this->vars[$name]))
          $this->vars[$name] = $this->getUncryptedValue ($this->vars[$name]);
    }

    function getUniqId ()
    {
      srand ((double) microtime () * 1000000);

      return md5 (rand (0, time ()));
    }

    function _keyEU ($txt, $encrypt_key)
    {
      $encrypt_key = md5 ($encrypt_key);
      $ctr = 0;
      $tmp = '';

      for ($i = 0; $i < strlen($txt); $i++)
      {
        if ($ctr == strlen ($encrypt_key))
          $ctr = 0;
        $tmp .= substr ($txt, $i, 1) ^ substr ($encrypt_key, $ctr, 1);
        $ctr++;
      }

      return $tmp;
    }

    function encrypt ($txt, $key)
    {
      $encrypt_key = $this->getUniqId ();
      $ctr = 0;
      $tmp = '';

      for ($i = 0; $i < strlen ($txt); $i++)
      {
        if ($ctr == strlen ($encrypt_key)) 
          $ctr = 0;
        $tmp .= substr ($encrypt_key, $ctr, 1) . 
          (substr ($txt, $i, 1) ^ substr ($encrypt_key, $ctr, 1));
        $ctr++;
      }

      return $this->_keyEU ($tmp, $key);
    }

    function unencrypt ($txt, $key)
    {
      $txt = $this->_keyEU ($txt, $key);
      $tmp = '';

      for ($i= 0; $i < strlen ($txt); $i++)
      {
        $md5 = substr ($txt, $i, 1);
        $i++;
        $tmp .= (substr ($txt, $i, 1) ^ $md5);
      }

      return $tmp;
    }

    function getUncryptedValue ($value)
    {
      if (!A_CRYPT_ENABLED)
        return $value;

      $value = ereg_replace ('^' . A_CRYPTED_PREFIX, '', $value);
      $value = $this->unencrypt (base64_decode ($value), $this->_previousKeyEU);

      return base64_decode ($value);
    }

    function getEncryptedValue ($value)
    {
      if (!A_CRYPT_ENABLED)
        return $value;

      $value = base64_encode ($value);

      return A_CRYPTED_PREFIX . 
        base64_encode ($this->encrypt ($value, $this->_currentKeyEU));
    }

    function getSerializedValue ($value)
    {
      return A_SERIALIZED_PREFIX . base64_encode (serialize ($value));
    }

    function getUnserializedValue ($value)
    {
      $value = ereg_replace ('^' . A_SERIALIZED_PREFIX, '', $value);
      return unserialize (base64_decode ($value));
    }

    function getCookie ($name)
    {
      if (@empty ($_COOKIE[$name]))
        return '';

      return unserialize (base64_decode ($_COOKIE[$name]));
    }

    function setCookie ($name, $value)
    {
      setcookie ($name, base64_encode (serialize ($value)), 0, '/');
    }

    function isSubmit ()
    {
      return ($this->vars['apazMainURL'] || $this->vars['apazRawURL']);
    }

    function htmlentities ($value)
    {
      return @htmlentities (
        urldecode ($value), ENT_QUOTES, $this->vars['pageEncoding']);
    }

    function utf8_decode ($value)
    {
      if (is_array ($value))
      {
        for ($i = 0; $i < count ($value); $i++)
          $value[$i] = $this->utf8_decode ($value[$i]);
      }
      else
      {
        return (preg_match (
          '%^(?:
             [\x09\x0A\x0D\x20-\x7E]
           | [\xC2-\xDF][\x80-\xBF]
           |  \xE0[\xA0-\xBF][\x80-\xBF]
           | [\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}
           |  \xED[\x80-\x9F][\x80-\xBF]
           |  \xF0[\x90-\xBF][\x80-\xBF]{2}
           | [\xF1-\xF3][\x80-\xBF]{3}
           |  \xF4[\x80-\x8F][\x80-\xBF]{2}
           )*$%s', $value)) ?
            utf8_decode ($value) : $value;
      }
    }

    function getPageEncoding ($buf)
    {
      if (!@$this->vars['pageEncoding'])
      {
        if (preg_match ('/meta.*http-equiv.*charset=([^\',",\>]+)/si', 
            $buf, $match))
          $this->vars['pageEncoding'] = strtolower ($match[1]);
        else
          $this->vars['pageEncoding'] = 'iso-8859-1';
      }

      return $this->vars['pageEncoding'];
    }

    function updateFileInfos ($mimeType)
    {
      $extension = 'html';

      if (($pos = strpos ($mimeType, ';')) !== false)
        $mimeType = trim (substr ($mimeType, 0, $pos));

      if (($pos = strpos ($mimeType, '/')) !== false)
        $extension = substr ($mimeType, $pos + 1, 
          strlen ($mimeType) - $pos - 1);

      $this->_fileInfos = $this->getFileInfos ('', $extension);
    }

    function getFileInfos ($filename = '', $extension = '')
    {
      $ret = array (
        'mimeType' => 'text/html',
        'raw' => 0,
        'incrustation' => 0
      );

      if ($filename != '')
      {
        if (($pos = strrpos ($filename, '.')) === false)
          return $ret;
      }

      $extension = ($extension != '') ?
        $extension : strtolower (substr ($filename, $pos + 1));

      switch ($extension)
      {
        case 'gif':
          $ret['mimeType'] = 'image/gif';
          $ret['raw'] = 1;
          break;
        case 'jpeg':
        case 'jpg':
        case 'jpe':
          $ret['mimeType'] = 'image/jpeg';
          $ret['raw'] = 1;
          break;
        case 'pcx':
          $ret['mimeType'] = 'image/pcx';
          $ret['raw'] = 1;
          break;
        case 'png':
          $ret['mimeType'] = 'image/png';
          $ret['raw'] = 1;
          break;
        case 'svg':
        case 'svgz':
          $ret['mimeType'] = 'image/svg+xml';
          $ret['raw'] = 1;
          break;
        case 'tiff':
        case 'tif':
          $ret['mimeType'] = 'image/tiff';
          $ret['raw'] = 1;
          break;
        case 'ico':
          $ret['mimeType'] = 'image/x-icon';
          $ret['raw'] = 1;
          break;
        case 'bmp':
          $ret['mimeType'] = 'image/x-ms-bmp';
          $ret['raw'] = 1;
          break;
        case 'xpm':
          $ret['mimeType'] = 'image/x-xpixmap';
          $ret['raw'] = 1;
          break;
        case 'ogg':
          $ret['mimeType'] = 'application/ogg';
          $ret['raw'] = 1;
          break;
        case 'mp3':
          $ret['mimeType'] = 'audio/mpeg';
          $ret['raw'] = 1;
          break;
        case 'pdf':
          $ret['mimeType'] = 'application/pdf';
          $ret['raw'] = 1;
          break;
        case 'asc':
        case 'txt':
        case 'text':
        case 'diff':
        case 'pot':
          $ret['mimeType'] = 'text/plain';
          $ret['raw'] = 1;
          break;
        case 'css':
          $ret['mimeType'] = 'text/css';
          $ret['raw'] = 0;
          break;
        case 'rss':
          $ret['mimeType'] = 'application/rss+xml';
          $ret['raw'] = 1;
          break;
        case 'html':
        case 'htm':
        case 'shtml':
          $ret['mimeType'] = 'text/html';
          $ret['raw'] = 0;
          $ret['incrustation'] = 1;
          break;
        case 'js':
          $ret['mimeType'] = 'text/javascript';
          $ret['raw'] = 0;
          break;
        case 'zip':
          $ret['mimeType'] = 'application/zip';
          $ret['raw'] = 1;
          break;
        case 'x-gtar':
        case 'gtar':
        case 'tgz':
        case 'taz':
          $ret['mimeType'] = 'application/x-gtar';
          $ret['raw'] = 1;
          break;
        case 'tar':
          $ret['mimeType'] = 'application/x-tar';
          $ret['raw'] = 1;
          break;
        default:
          $ret['incrustation'] = 0;
      }

      return $ret;
    }

    function init ()
    {
      $this->_mainContent = '';

      if (!@$this->vars['initBasePath'])
        $this->vars['initBasePath'] = $this->vars['apazBasePath'];

      if ($this->vars['apazRawURL'])
      {
        $this->vars['apazMainURL'] = $this->vars['apazRawURL'];
        $this->vars['apazCurrentURL'] = $this->vars['apazRawURL'];
      }

      /* Set aPAz script URL */
      if (!$this->setApazScriptURL ())
        return false;

      /* Set main URL */
      if (!$this->setApazMainURL ())
        return false;

      /* Set current URL */
      if (!$this->setApazCurrentURL ())
        return false;

      /* If current URL is different than main URL we are in another
       * Web site, so change main URL to reflect this change. */
      if (
        $this->vars['apazCurrentURLStruct']['host'] != '' &&
        $this->vars['apazMainURLStruct']['host'] != 
          $this->vars['apazCurrentURLStruct']['host'])
      {
        $this->vars['apazMainURL'] = $this->vars['apazCurrentURL'];
        $this->vars['apazMainURLStruct'] = $this->vars['apazCurrentURLStruct'];
      }

      if (preg_match ('/\.(.*?){1,5}$/', 
          $this->vars['apazCurrentURLStruct']['path']))
        $this->vars['apazBasePath'] = 
          dirname ($this->vars['apazCurrentURLStruct']['path']);
      else
        $this->vars['apazBasePath'] = 
          $this->vars['apazCurrentURLStruct']['path'];

      $this->cleanURLs ();

      if ($this->vars['apazCurrentURLStruct']['scheme'] != 'http')
      {
        $this->_errno = 1;
        $this->_errstr = 
          "Sorry, but for the moment aPAz only support HTTP protocol";
        $this->_errurl = $this->vars['apazCurrentURL'];

        $this->useHistory ($this->vars['apazHistoryIndex']);
        $this->vars['apazHistoryIndex']++;

        return;
      }

      $this->_scriptServer = $this->vars['apazScriptURL'];
      $this->_basePath = $this->vars['apazBasePath'];
      $this->_mainServer = 
        $this->vars['apazMainURLStruct']['scheme'] . '://' . 
        $this->vars['apazMainURLStruct']['host'] . ':' . 
        $this->vars['apazMainURLStruct']['port'];

      $this->initCookies ();
    }

    function process ()
    {
      $this->connect (
        $this->vars['apazCurrentURLStruct']['host'], 
        $this->vars['apazCurrentURLStruct']['port']
      );

      if ($this->getMainContent () === false)
      {
        $this->_mainContent = '';

        $this->init ();
        $this->process ();
      }
      else
        $this->normalizeMainContent ();
    }

    function getErrorPageHTML ()
    {
      $this->_fileInfos['incrustation'] = 1;

      return "
        <html><head><title>aPAz - A Php AnonymiZer " . APP_VERSION . "</title>
        <style>
          div.apazError
          {
            text-align: center;
            color: black;
            font-family: Arial,Helvetica;
            font-size: 16px;
            font-weight: bold;
            padding: 5px;
          }
          span.apazError {color: green;}
        </style></head><body>
        <br /><br /><br /><br /><br /><br />
        <div class='apazError'>
           [&nbsp;<a href=\"" . $this->_errurl . "\">" . 
            $this->_errurl . "</a>&nbsp;]
          <p /><span class='apazError'>" . $this->_errstr . "</span><p />
           Please, check your input.
        </div></body></html>
        ";
    }

    function useHistory ($index)
    {
      if (isset ($this->vars['apazHistory'][$index]))
      {
        $history = $this->vars['apazHistory'][$index];

        $this->vars['apazMainURL'] = $history['apazMainURL'];
        $this->vars['apazCurrentURL'] = $history['apazCurrentURL'];
        $this->vars['apazFormMethod'] = $history['apazFormMethod'];
        $this->formVars = unserialize ($history['formVars']);
      }
    }

    function canAddToCookies ()
    {
      return (isset ($this->vars['currentHeader']['set-cookie']));
    }

    function getMainServerCookies ($path)
    {
      $ret = '';

      if (
          !isset ($this->_cookies[$this->_mainServer]) ||
          !is_array ($this->_cookies[$this->_mainServer]))
        return '';

      foreach ($this->_cookies[$this->_mainServer] as $name => $cookie)
        if (ereg ('^' . $cookie['path'], $path))
          $ret .= "$name=" . $cookie['value'] . '; ';

      $ret = ereg_replace ('; $', '', $ret);

      return $ret;
    }

    function addToCookies ()
    {
      $cookies = $this->vars['currentHeader']['set-cookie'];
      if (!is_array ($cookies))
        $cookies = array ($cookies);

      if (!isset ($this->_cookies[$this->_mainServer]))
        $this->_cookies[$this->_mainServer] = array ();

      // We manage neither expire date nor domain.
      foreach ($cookies as $item)
      {
        $path = $this->_basePath;

        if  (strpos ($item, ';') === false)
          $cookie = $item;
        else
        {
          $infos = explode (';', $item);
          $cookie = $infos[0]; unset ($infos[0]);
          foreach ($infos as $info)
            if (ereg ('^path', $info))
            {
              $info = preg_replace ("/(\r|\n)/", '', $info);
              list (, $path) = explode ('=', $info);
              break;
            }
        }

        list ($name, $value) = explode ('=', $cookie);
        $this->_cookies[$this->_mainServer][$name] = array (
          'value' => $value,
          'path' => $path
        );
      }

      $this->setCookie ('cookies', $this->_cookies);
    }

    function initCookies ()
    {
      $this->_cookies = $this->getCookie ('cookies');
    }

    function canAddToHistory ()
    {
      return (
        !$this->_firstTime &&
        !$this->_errno &&
        !$this->vars['apazUseHistory']
      );
    }

    function addToHistory ()
    {
      $this->vars['apazHistoryIndex']++;

      if (!is_array ($this->vars['apazHistory']))
        $this->vars['apazHistory'] = array ();

      $this->vars['apazHistory'][$this->vars['apazHistoryIndex']] = array (
        'apazMainURL' => $this->vars['apazCurrentURL'],
        'apazCurrentURL' => $this->vars['apazCurrentURL'],
        'apazFormMethod' => $this->vars['apazFormMethod'],
        'formVars' => serialize ($this->formVars)
      );
    }

    function getDefaultPageHTML ()
    {
      $this->_fileInfos['incrustation'] = 1;

      return "
        <html><head><title>aPAz - A Php AnonymiZer " . APP_VERSION . "</title>
        <style>
        </style></head><body>
        </body></html>
        ";
    }

    function displayMainContentRaw ()
    {
      print $this->_mainContent;

      $this->done ();

      exit;
    }

    function displayMainContent ()
    {
      /* Send content-type to the browser */
      if (@$this->_fileInfos['mimeType'] != '')
        header ('Content-Type: ' . $this->_fileInfos['mimeType']);

      if (
          (@$this->_fileInfos['raw']) || !$this->_fileInfos['incrustation'])
      {
        $this->displayMainContentRaw ();
        return;
      }

      /* Get/Remove end tags to install our code in current page content */
      if (preg_match (
        '/<\/(body|noframes|frameset)>([^>]*)<\/html>\s*[^--\>]?/si', 
        $this->_mainContent, $match))
      {
        if (!$this->vars['apazFrame'])
          $this->vars['apazFrame'] = eregi ('frame', $match[1]);

        $this->_mainContent = preg_replace (
          '/<\/(body|noframes|frameset)>(.*)<\/html>/si', 
          '',
          $this->_mainContent
        );

        $this->_endTags = '</' . $match[1] . '>' . $match[2] . '</html>';
      }

      /* Try to determinate page encoding */
      $this->vars['pageEncoding'] = 
        $this->getPageEncoding ($this->_mainContent);

      if ($this->canAddToHistory ())
        $this->addToHistory ();

      /* Display first content part */
        print $this->_mainContent;
    }

    function displayEndTags ()
    {
      /* Display second content part (HTML end tags) */
      print $this->_endTags;
    }

    // FIXME
    function getAbsoluteURL ($url, $basePath)
    {
      $new = '';

      $url = $this->cleanBufferURLs ($url);
      $basePath = $this->vars['apazBasePath'];

      if ($url{0} != '/' && !eregi ("^$basePath", $url))
        $url = "$basePath/$url";

      $url = preg_replace (
        array (
          '/\/+/',
          '/^\/\./',
          '/([^\.]\.\/)/'
        ), 
        array (
          '/',
          '\.',
          '/'
        ), 
        $url
      );

      for ($i = 0; $i < strlen ($url); $i++)
      {
        if (substr ($url, $i, 3) != '../')
          $new .= $url{$i};
        else
        {
          $new = substr ($new ,0, strlen ($new) - 1);
          if ($new)
            $new = substr ($new, 0, strrpos ($new, '/'));
          $i++;
        }
      }

      return $new;
    }

    function normalizeMainContentRaw ()
    {
      if ($this->_errno) return;

      $p = strpos ($this->_mainContent, "\r\n\r\n") + 4;
      $this->_mainContent = 
        substr ($this->_mainContent, $p, strlen ($this->_mainContent) - $p);
    }

    /* FIXME 
     * 2/ contenu += "<a href=\"#\" onClick=\"addHomepage(this);\">label</a>";
     * -> give :
     * contenu += "<a  href="javascript:apazPost('\"#\" onClick=\"addHomepage(this);\"')">label</a>";
     * 3/ <a href="/web/page.php?keyword=assurance sante&accroche=Comparez les mutuelles">label</a>
     * -> give:
     * <a href= javascript:apazPost('/web/page.pho?keyword=assurance') sante&accroche=Comparez les mutuelles">label</a>
     */
    function _processHTML_A_HREF_cb ($a)
    {
      if ($a[5] == '"')
        return "$a[1]$a[2]<a $a[3] href=$a[4]$a[5]$a[6]";

      $dum = '';
      if ($a[6] == '>') 
      {
        $a[6] = '"'; 
        $dum = '>';
      }

      if (preg_match ('/\w\+\w/i', $a[5]) || 
          eregi ('(javascript|mailto)', $a[5]))
        return "$a[1]$a[2]<a $a[3] href=$a[4]$a[5]$a[6]$dum";

      if ($a[6] == "'")
      {
        $apos = ($a[1] == '"') ? '\"' : '"';
        $link = ereg_replace ('(%22|")', '\"', $a[5]);
      }
      else
      {
        $apos = ($a[1] == "'") ? "\\'" : "'";
        $link = ereg_replace ("(\%27|')", "\\'", $a[5]);
      }

      $link = ($link{0} == '#') ?
        urlencode (urldecode ($link)) :
        urlencode ($this->getEncryptedValue (urldecode ($link)));

      return "$a[1]$a[2]<a $a[3] " .
        "href=$a[6]javascript:apazPost($apos$link$apos)$a[6]$dum";
    }

    function _processHTML_LINK_HREF_cb ($a)
    {
      $proto = eregi ('^(http|ftp)', $a[3]);

      if ($proto)
        $link = $a[3];
      elseif ($a[3]{0} == '/')
        $link = $this->_mainServer . $a[3];
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $a[3];
 
      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));
  
      return 
        "<link $a[1] href=$a[2]" . $this->_scriptServer . 
        "?apazRawURL=$link$a[4]";
    }

      /* HTML - IMG, IMAGE, SCRIPT, INPUT, IFRAME, FRAME */
    function _processHTML_IMAGES_SCRIPT_INPUT_FRAMES_cb ($a)
    {
      if (
          empty ($a[4]) ||
          /* Remove google-analytics links */
          eregi ('google-analytics', $a[4]))
        return
          "$a[1]$a[2] src=$a[3]$a[5]";

      $proto = eregi ('^(http|ftp)', $a[4]);

      if ($proto)
        $link = $a[4];
      elseif ($a[4]{0} == '/')
        $link = $this->_mainServer . $a[4];
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $a[4];

      $apazFrame = '';
      if (eregi ('frame', $a[1]))
        $apazFrame = 'apazFrame=1&';

      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));

      return 
        "$a[1]$a[2] src=$a[3]" . $this->_scriptServer . 
        "?${apazFrame}apazRawURL=$link$a[5]";
    }

    function _processHTML_BACKGROUND_ACTION_cb ($a)
    {
      if (strpos ($a[5], '/') === false && substr_count ($a[5], '.') > 1)
        return "<$a[1]$a[2]$a[3]=$a[4]$a[5]$a[6]$a[7]>";

      if (empty ($a[5]))
        $a[5] = $this->vars['apazCurrentURL'];
    
      $proto = eregi ('^(http|ftp)', $a[5]);

      if ($proto)
        $link = $a[5];
      elseif ($a[5]{0} == '/')
        $link = $this->_mainServer . $a[5];
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $a[5];

      $link = $this->getEncryptedValue ($link);

      /* If this is a form, do transformation to hijack post/get data */
      // FIXME We must try to deal with the "onSubmit" attribute.
      if (strtolower ($a['3']) == 'action')
      {
        $apazFormMethod = '';

        if (preg_match ('/method\s*=\s*(\'|"|\s)?([^\'"\s]*)/', 
          $a[1], $match))
        {
          $a[1] = preg_replace ('/method\s*=\s*(\'|"|\s)?([^\'"\s]*)/',
            'method=\\1post', $a[1]);
          $apazFormMethod = $match[2];
        }
        elseif (preg_match ('/method\s*=\s*(\'|"|\s)?([^\'"\s]*)/', 
          $a[7], $match))
        {
          $a[7] = preg_replace ('/method\s*=\s*(\'|"|\s)?([^\'"\s]*)/',
            'method=\\1post', $a[7]);
          $apazFormMethod = $match[2];
        }
        else
        {
          $a[1] .= " method=post ";
          $apazFormMethod = 'get';
        }
  
        $link = htmlentities ($link);
        $a[7] .= ">\n
          <input type='hidden' name='apazFormMethod' value='$apazFormMethod' />
          <input type='hidden' name='apazCurrentURL' value='$link' />\n". 
          $this->writeApazHiddenFields (true);

        $ret = 
          "<$a[1]$a[2]$a[3]=$a[4]" .  $this->_scriptServer . 
          "$a[6]$a[7]";
      }
      else
      {
        $link = urlencode (urldecode ($link));
        $ret =  
          "<$a[1]$a[2]$a[3]=$a[4]" . $this->_scriptServer . 
          "?apazRawURL=$link$a[6]$a[7]>";
      }

      return $ret;
    }

    function _processCSS_URL_cb ($a)
    {
      $link = "$a[3]$a[4]";

      if (strpos ($a[4], '.') === false)
        return "$a[1]url$a[2]$a[3]$a[4]$a[5]$a[6]";

      $proto = eregi ('^(http|ftp)', $link);

      if ($proto)
        ;
      elseif ($link{0} == '/')
        $link = $this->_mainServer . $link;
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $link;

      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));

      return 
        "$a[1]url$a[2]" . $this->_scriptServer . 
        "?apazRawURL=$link$a[5]$a[6]";
    }

    function _processCSS_IMPORT_cb ($a)
    {
      $proto = eregi ('^(http|ftp)', $a[2]);

      if ($proto)
        $link = $a[2];
      elseif ($a[2]{0} == '/')
        $link = $this->_mainServer . $a[2];
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $a[2];

      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));

      return 
        "$a[1]@import \"" . $this->_scriptServer . 
        "?apazRawURL=$link\"$a[3]";
    }

    function _processJAVASCRIPT_SRC_cb ($a)
    {
      if (strpos ($a[2], '.') === false || eregi ('^eval', $a[2]))
        return ".src=$a[1]$a[2]$a[3]";

      $proto = eregi ('^(http|ftp)', $a[2]);

      if ($proto)
        $link = $a[2];
      elseif ($a[2]{0} == '/')
        $link = $this->_mainServer . $a[2];
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $a[2];

      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));

      return 
        ".src=$a[1]" . $this->_scriptServer . 
        "?apazRawURL=$link$a[3]";
    }

    function _processJAVASCRIPT_URL_ASSIGNATION_cb ($a)
    {
      if (
          strpos ($a[3], '.') === false || 
          strpos ($a[3], '[') !== false || 
          $a[3]{0} == '+' || 
          eregi ('^(eval|window\.|document\.)', $a[3]))
        return "$a[1]=$a[2]$a[3]$a[4]";

      $proto = eregi ('^(http|ftp)', $a[3]);

      if ($proto)
        $link = $a[3];
      elseif ($a[3]{0} == '/')
        $link = $this->_mainServer . $a[3];
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $a[3];

      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));

      return 
        "$a[1]=$a[2]" . $this->_scriptServer . 
        "?apazRawURL=$link$a[4]";
    }

    function _processJAVASCRIPT_LOCATION_cb ($a)
    {
      if (
          (strpos ($a[3], '.') === false && strpos ($a[3], '/') === false) || 
          eregi ('^(eval|window\.|document\.)', $a[3]))
        return ".location.href=$a[2]$a[3]$a[4]";

      $proto = eregi ('^(http|ftp)', $a[3]);

      if ($proto)
        $link = $a[3];
      elseif ($a[3]{0} == '/')
        $link = $this->_mainServer . $a[3];
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $a[3];

      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));

      return 
        ".location.href=$a[2]" . $this->_scriptServer . 
        "?apazRawURL=$link$a[4]";
    }

    function _processJAVASCRIPT_OPEN_cb ($a)
    {
      if (strpos ($a[2], '.') === false)
        return "open($a[1]$a[2]$a[3]";

      $proto = eregi ('^(http|ftp)', $a[2]);

      if ($proto)
        $link = $a[2];
      elseif ($a[2]{0} == '/')
        $link = $this->_mainServer . $a[2];
      else
        $link = $this->_mainServer . '/' . $this->_basePath . '/' . $a[2];

      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));

      return 
        "open($a[1]" . $this->_scriptServer . 
        "?apazRawURL=$link$a[3]";
    }

    function _processALL_OtherLinks_cb ($a)
    {
      $link = "$a[2]://$a[3]";
      if (strpos ($a[3], 'apazRawURL') !== false ||
          strpos ($link, $this->_mainServer) == 0)
        return "=$a[1]$link$a[4]";

      $link = urlencode ($this->getEncryptedValue (urldecode ($link)));

      return 
        "=$a[1]" . $this->_scriptServer . 
        "?apazRawURL=$link$a[4]";
    }

    function _processALL_Comments_cb ($a)
    {
      return (preg_match ('/\<(style|script)/', $a[1])) ?
        "$a[1]$a[2]" : $a[1];
    }

    // FIXME
    function normalizeMainContent ()
    {
      if ($this->_errno) return;

      /* If data must not be modified (images etc.) */
      if ($this->_fileInfos['raw'])
      {
        $this->normalizeMainContentRaw ();
        return;
      }

      $p = strpos ($this->_mainContent, "\r\n\r\n") + 4;
      $this->_mainContent = 
        substr ($this->_mainContent, $p, strlen ($this->_mainContent) - $p);

      $this->_mainContent = preg_replace (
        array (
          /* Remove all targets */
          '/target\s*=\s*(\'|")?\s*[\w]+(\s|\'|")?/si',
          /* Remove AsSolution tags */
          '/\<\!--([^>]+)BEGIN\s*:\s*AdSolution(.*?)END\s*:\s*AdSolution([^>]+)--\>/si',
        ), 
        array (
          '',
          ''
        ), 
        $this->_mainContent 
      );

      /* Remove all HTML comments (but take care of HTML javascript and 
       * style comments) */
      $this->_mainContent = preg_replace_callback (
        '/(<[^>]*>)?<!--([^#]?[^--]*[^\/\/]\s+)-->/si',
        array ($this, '_processALL_Comments_cb'),
        $this->_mainContent
      );

      /* Relatives URLs conversion */
      // FIXME ne prend en compte que ce qui commence par du relatif. Il 
      // faudrait modifier tout ce qui *contient* du relatif.
      if (preg_match_all (
        '/(href|src|url|import|background)\s*(=|\()?\s*(\'|")?\s*\.(.*?)\\3/si', 
        $this->_mainContent, $match))
      foreach ($match[4] as $link)
      {
        $absolute = $this->getAbsoluteURL (".$link", $this->_basePath);
        $link = ereg_replace ('/', '\/', $link);
        $link = ereg_replace ('\.', '\\.', $link);
        $this->_mainContent = 
          preg_replace ("/\.$link/", $absolute, $this->_mainContent);
      }

      /* HTML - A HREF */
      $this->_mainContent = preg_replace_callback (
        '/(.)?(\s*)<\s*a\s*([^>]*)\s*href\s*=\s*([\',"])?\s*([^\\4].*?)(\\4|\s|\>)/si',
        array ($this, '_processHTML_A_HREF_cb'),
        $this->_mainContent 
      );

      /* HTML - LINK HREF */
      $this->_mainContent = preg_replace_callback (
        '/<\s*link\s*([^>]*)\s*href\s*=\s*(\'|")?\s*(.*?)(\s|\'|\"|\>)/si',
        array ($this, '_processHTML_LINK_HREF_cb'),
        $this->_mainContent 
      );

      /* HTML - IMG, IMAGE, SCRIPT, INPUT, IFRAME, FRAME */
      $this->_mainContent = preg_replace_callback (
        '/(img|image|script|input|iframe|frame)([^>]*)\s+src\s*=\s*(\'|"|\s)?\s*(.*?)(\s|\'|"|\>)/si',
        array ($this, '_processHTML_IMAGES_SCRIPT_INPUT_FRAMES_cb'),
        $this->_mainContent 
      );

      /* HTML - BACKGROUND, ACTION */
      $this->_mainContent = preg_replace_callback (
        '/<([^>]*)(\s*)(background|action)\s*=\s*(\'|"|\s)?\s*([^\'"\s\>]*)(\'|"|\s)?([^>]*)\>/si',
        array ($this, '_processHTML_BACKGROUND_ACTION_cb'),
        $this->_mainContent 
      );

      /* CSS - URL */
      $this->_mainContent = preg_replace_callback (
        '/(\W)url\s*([\s,\',",\(]+)([a-z,\/])\s*(.*?)([\',",\s,\)])\s*(\)?)/si',
        array ($this, '_processCSS_URL_cb'),
        $this->_mainContent 
      );

      /* CSS - IMPORT */
      $this->_mainContent = preg_replace_callback (
        '/(\W)@import\s*[\',"]+\s*(.*?)[\',"]+(\s*)/si',
        array ($this, '_processCSS_IMPORT_cb'),
        $this->_mainContent 
      );

      /* Javascript - images SRC */
      $this->_mainContent = preg_replace_callback (
        '/\.src\s*=\s*(\'|"|\s)?\s*(.*?)(\s|\'|"|\>)/si',
        array ($this, '_processJAVASCRIPT_SRC_cb'),
        $this->_mainContent 
      );

      /* Javascript - url variables assignation (hum...) */
      $this->_mainContent = preg_replace_callback (
        '/([^apazRaw]url)\s*=\s*(\'|"|\s)?\s*(.*?)(\s|\'|"|;)/si',
        array ($this, '_processJAVASCRIPT_URL_ASSIGNATION_cb'),
        $this->_mainContent 
      );

      /* Javascript - LOCATION */
      $this->_mainContent = preg_replace_callback (
        '/\.location(\.href)?\s*=\s*(\'|"|\s)?\s*(.*?)(\s|\'|"|\>)/si',
        array ($this, '_processJAVASCRIPT_LOCATION_cb'),
        $this->_mainContent 
      );

      /* Javascript - OPEN functions' link */
      $this->_mainContent = preg_replace_callback (
        '/open\s*\(\s*(\'|")?\s*([^\'"]*)?\s*(\'|")*/si',
        array ($this, '_processJAVASCRIPT_OPEN_cb'),
        $this->_mainContent 
      );

      /* Javascript/HTML - The other links */
      $this->_mainContent = preg_replace_callback (
        '/=\s*(\'|")\s*(http|https|ftp)\:\/\/(.*?)(\'|")/si',
        array ($this, '_processALL_OtherLinks_cb'),
        $this->_mainContent 
      );
    }

    function normalizeScriptURL ()
    {
      /* Host */
      $this->vars['apazScriptURLStruct']['host'] = 
        strtolower ($this->vars['apazScriptURLStruct']['host']);

      /* Path */
      if (!isset ($this->vars['apazScriptURLStruct']['path']))
        $this->vars['apazScriptURLStruct']['path'] = '/';
    }

    function normalizeMainURL ()
    {
      /* Host */
      $this->vars['apazMainURLStruct']['host'] = 
        strtolower (@$this->vars['apazMainURLStruct']['host']);

      /* Port */
      if (!isset ($this->vars['apazMainURLStruct']['port']))
        $this->vars['apazMainURLStruct']['port'] = 80;

      /* Path */
      if (!isset ($this->vars['apazMainURLStruct']['path']))
        $this->vars['apazMainURLStruct']['path'] = '/';
    }

    function normalizeCurrentURL ()
    {
      /* Scheme */
      if (!isset ($this->vars['apazCurrentURLStruct']['scheme']))
        $this->vars['apazCurrentURLStruct']['scheme'] = 
          @$this->vars['apazMainURLStruct']['scheme'];

      /* Host */
      if (!isset ($this->vars['apazCurrentURLStruct']['host']))
        $this->vars['apazCurrentURLStruct']['host'] = 
          $this->vars['apazMainURLStruct']['host'];
      $this->vars['apazCurrentURLStruct']['host'] = 
        strtolower ($this->vars['apazCurrentURLStruct']['host']);

      /* Port */
      if (!isset ($this->vars['apazCurrentURLStruct']['port']))
        $this->vars['apazCurrentURLStruct']['port'] = 
          $this->vars['apazMainURLStruct']['port'];

      /* Path */
      if (!isset ($this->vars['apazCurrentURLStruct']['path']))
        $this->vars['apazCurrentURLStruct']['path'] = 
          $this->vars['apazMainURLStruct']['path'];
      elseif ($this->vars['apazCurrentURLStruct']['path']{0} != '/')
        $this->vars['apazCurrentURLStruct']['path'] = 
          $this->vars['apazMainURLStruct']['path'] . '/' . 
            $this->vars['apazCurrentURLStruct']['path']; 
    }

    function cleanBufferURLs ($str)
    {
      return preg_replace ('/([a-z,0-9]+)(\/+)/i', '\\1/', $str);
    }

    function cleanURLs ()
    {
      $this->vars['apazMainURLStruct']['path'] =
        $this->cleanBufferURLs ($this->vars['apazMainURLStruct']['path']);
      $this->vars['apazCurrentURLStruct']['path'] = 
        $this->cleanBufferURLs ($this->vars['apazCurrentURLStruct']['path']);
      $this->vars['apazMainURL'] = 
        $this->cleanBufferURLs ($this->vars['apazMainURL']); 
      $this->vars['apazCurrentURL'] = 
        $this->cleanBufferURLs ($this->vars['apazCurrentURL']);
      $this->vars['initBasePath'] = 
        $this->cleanBufferURLs ($this->vars['initBasePath']); 
      $this->vars['apazBasePath'] = 
        $this->cleanBufferURLs ($this->vars['apazBasePath']);
    }

    function connect ($host, $port)
    {
      if ($this->_errno) return;

      $this->close ();

      $this->_socket = @fsockopen (
        $host, $port, 
        $this->_errno, $this->_errstr, 
        A_CONNECTION_TIMEOUT
      );

      if (!$this->_socket)
      {
        $this->_errno = 1;
        $this->_errstr = "An error occured while connecting to the host";
        return;
      }
    }

    function getHTTPUserAgent ()
    {
      $userAgent = 
        'Mozilla/5.0 (X11; U; Linux i686; fr; rv:1.8.0.4) ' .
        'Gecko/20060406 Firefox/1.5.0.4';

      if (isset ($_SERVER['HTTP_USER_AGENT']))
        $userAgent = $_SERVER['HTTP_USER_AGENT'];

      return $userAgent;
    }

    function getFormVarsURLEncoded ($vars, $arrName = '')
    {
      $ret = '';

      foreach ($vars as $k => $v)
      {
        if (is_array ($v))
          $ret .= $this->getFormVarsURLEncoded ($v, $k);
        else
        {
          if ($arrName)
          {
            if (is_numeric ($k)) $k = '';
            $k = $arrName . "[$k]";
          }

          $ret .= "$k=" . urlencode ($v) . '&';
        }
      }

      return $ret;
    }

    // FIXME Use something cleaner than this bad stuff...
    function getNormalizedHTTPRequestURL ($url)
    {
      $url = urlencode (str_replace (
        array ('&amp;', '?', '/', '&', '=', '#', ';'),
        array ('&', 'apazSUBST1', 'apazSUBST2', 'apazSUBST3', 'apazSUBST4',
               'apazSUBST5', 'apazSUBST6'),
        urldecode ($url)
      ));

      return str_replace (
        array ('apazSUBST1', 'apazSUBST2', 'apazSUBST3', 'apazSUBST4',
               'apazSUBST5', 'apazSUBST6'),
        array ('?', '/', '&', '=', '#', ';'),
        $url
      );
    }

    function getMainContent ()
    {
      $referer =
        $this->vars['apazCurrentURLStruct']['scheme'] . '://' . 
        $this->vars['apazCurrentURLStruct']['host'];
      $referer .= @$this->vars['apazCurrentURLStruct']['path'];

      $acceptCharset = (isset ($_SERVER['HTTP_ACCEPT_CHARSET']) && 
          $_SERVER['HTTP_ACCEPT_CHARSET']) ?
        $_SERVER['HTTP_ACCEPT_CHARSET'] : 'ISO-8859-1,utf-8;q=0.7,*;q=0.7';

      $acceptLanguage = ($_SERVER['HTTP_ACCEPT_LANGUAGE']) ?
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] : 'en';

      /* Common part for requests */
      $common = sprintf (
        "User-Agent: %s\r\n" .
        "Host: %s\r\n" .
        "Referer: %s\r\n" .
        "Accept-Charset: %s\r\n" .
        "Accept-Language: %s\r\n" .
        "Accept: */*\r\n",
        $this->getHTTPUserAgent (),
        $this->vars['apazCurrentURLStruct']['host'],
        $referer,
        $acceptCharset,
        $acceptLanguage
      );

      if ($cookies = $this->getMainServerCookies ($this->_basePath))
        $common .= "Cookie: $cookies\r\n";

      /* If all is ok, retreive data from the host */
      if (!$this->_errno)
      {
        /* Form submit POST */
        if ($this->vars['apazFormMethod'] == 'post')
        {
          $args = $this->getFormVarsURLEncoded ($this->formVars);

          $url = $this->vars['apazCurrentURLStruct']['path'];
          $url .= isset ($this->vars['apazCurrentURLStruct']['query']) ?
            '?' . $this->vars['apazCurrentURLStruct']['query'] : '';
          $url .= isset ($this->vars['apazCurrentURLStruct']['fragment']) ?
            '#' . $this->vars['apazCurrentURLStruct']['fragment'] : '';

          /* Build query */
          $query =
            "POST " . $this->getNormalizedHTTPRequestURL ($url) . 
              " HTTP/1.0\r\n" .
            $common .
            "Content-Type: application/x-www-form-urlencoded\r\n" .
            "Content-Length: " . strlen ($args) . "\r\n" .
            "\r\n" .
            $args;
        }
        /* Form submit GET */
        elseif ($this->vars['apazFormMethod'] == 'get')
        {
          $args = $this->getFormVarsURLEncoded ($this->formVars);

          if (!isset ($this->vars['apazCurrentURLStruct']['query']))
            $this->vars['apazCurrentURLStruct']['query'] = '';

          $this->vars['apazCurrentURLStruct']['query'] .= "&$args";

          $url = $this->vars['apazCurrentURLStruct']['path'];
          $url .= '?' . $this->vars['apazCurrentURLStruct']['query'];

          /* Build query */
          $query = 
            "GET " . $this->getNormalizedHTTPRequestURL ($url) . 
              " HTTP/1.0\r\n" .
            "$common" .
            "\r\n";
        }
        /* Default GET request */
        else
        {
          $url = $this->vars['apazCurrentURLStruct']['path'];
          $url .= isset ($this->vars['apazCurrentURLStruct']['query']) ?
            '?' . $this->vars['apazCurrentURLStruct']['query'] : '';
          $url .= isset ($this->vars['apazCurrentURLStruct']['fragment']) ?
            '#' . $this->vars['apazCurrentURLStruct']['fragment'] : '';

          /* Build query */
          $query = 
            "GET " . $this->getNormalizedHTTPRequestURL ($url) . 
              " HTTP/1.0\r\n" .
            $common . 
            "\r\n";
        }

        /* Execute query */
        fwrite ($this->_socket, $query);
     
        /* Get data */
        $buf = '';
        while (!feof ($this->_socket))
          $buf .= fread ($this->_socket, 8192);
  
        /* Get HTTP header */
        $this->vars['currentHeader'] = $this->getHTTPHeader ($buf);

        /* Check if there is a immediate HTTP META refresh */
        if (
            preg_match ('/meta.*http-equiv.*\W0\s*;\s*url=([^\',",\>]+)/i', 
              $buf, $match) &&
            $match[1] != $this->vars['apazCurrentURL'])
          $this->vars['currentHeader']['location'] = $match[1];

        /* Check from header if data is on another location */
        if (isset ($this->vars['currentHeader']['location']))
        {
          if ($this->vars['apazFormMethod'])
          {
            $this->vars['apazRawURL'] = '';
            $this->vars['apazFormMethod'] = '';
          }

          $this->vars['apazCurrentURL'] = 
            $this->vars['currentHeader']['location'];
 
          if (eregi ('^(http|ftp)', $this->vars['apazCurrentURL']))
          {
            $this->vars['apazRawURL'] = $this->vars['apazCurrentURL'];
            $this->vars['apazMainURL'] = $this->vars['apazCurrentURL'];
          }

          $this->vars['apazBasePath'] = $this->vars['initBasePath'];

          return false;
        }
        /* Check HTTP status code */
        elseif ($this->isHTTPError ($this->vars['currentHeader']['code']))
        {
          $this->_errno = $this->vars['currentHeader']['code'];
          $this->_errstr = 
            $this->_config['HTTPCodes'][$this->vars['currentHeader']['code']];
        }
        else
        {
          /* Get file informations */
          $this->updateFileInfos ($this->vars['currentHeader']['content-type']);
          $this->_mainContent = $buf;
        }
      }

      /* If a error occured, build a error page */
      if ($this->_errno)
        $this->_mainContent = $this->getErrorPageHTML ();
      elseif ($this->canAddToCookies ())
        $this->addToCookies ();
    }

    function isHTTPError ($code)
    {
      return (in_array ($code, array (
        '401',
        '403',
        '404'
      )));
    }

    function getHTTPHeader ($content)
    {
      $ret = array ();

      $p = strpos ($content, "\r\n\r\n");
      $header = substr ($content, 0, $p + 1);

      /* Get HTTP response code */
      preg_match ('/(\d{3})/', $header, $match);
      $ret['code'] = $match[1];

      /* Get other HTTP header data */
      preg_match_all ("/^(.*?):\s+(.*)$/m", $header, $match);
      for ($i = 0; $i < count ($match[1]); $i++)
      {
        $key = strtolower ($match[1][$i]);
        $value = $this->utf8_decode (urldecode ($match[2][$i]));

        if (isset ($ret[$key]))
        {
          if (is_array ($ret[$key]))
            $ret[$key][] = $value;
          else
          {
            $old = $ret[$key];
            $ret[$key] = array ($old, $value);
          }
        }
        else
          $ret[$key] = trim ($match[2][$i]);
      }

      return $ret;
    }

    function close ()
    {
      if ($this->_socket)
        fclose ($this->_socket);
    }

    function getHTTPVar ($name, $default = '')
    {
      $ret = $default;
  
      if (isset ($_GET[$name]))
        $ret = $_GET[$name];
      elseif (isset ($_POST[$name]))
        $ret = $_POST[$name];
  
      $ret = $this->utf8_decode ($ret);
  
      return $ret;
    }

    function done ()
    {
      $this->close ();
    }

    function getShortenString ($str)
    {
      return (strlen ($str) > 80) ? 
        substr ($str, 0, 80) . '...' : $str;
    }

    function browserIsIE ()
    {
      return (strpos ($_SERVER['HTTP_USER_AGENT'], 'MSIE') !== false);
    }

    function isError ()
    {
      return ($this->_errno != 0);
    }

    function writeApazHiddenFields ($exludeApazCurrentURL = false)
    {
      $ret = '
  <input type="hidden" name="apazUseHistory" value="0" />
  <input type="hidden" name="apazHistoryIndex"
         value="' . htmlentities ($this->vars['apazHistoryIndex']) . '" />
  <input type="hidden" name="apazHistory"
         value="' . htmlentities ($this->getSerializedValue (
          $this->vars['apazHistory'])) . '" />
  <input type="hidden" name="apazBoxState" id="apazBoxState"
         value="' . htmlentities ($this->vars['apazBoxState']) . '" />
  <input type="hidden" name="apazMainURL" 
         value="' . $this->htmlentities ($this->vars['apazMainURL']) . '" />
  <input type="hidden" name="apazBasePath" 
         value="' . $this->htmlentities ($this->vars['apazBasePath']) . '" />';

      if (!$exludeApazCurrentURL)
        $ret .= '
  <input type="hidden" name="apazCurrentURL" 
         value="' . 
          $this->htmlentities ($this->vars['apazCurrentURL']) . '" />';
      
      return $ret;
    }
  }

  function debug ($var)
  {
    print "<pre>\n";
    print "aPAz - DEBUG\n";
    print_r ($var);
    print "</pre>\n";
  }

  $apaz = new APAz ($config);
  $apaz->displayMainContent ();
?>

<!-- ///////////////////////// -->
<!-- BEGIN - aPAz incrustation -->
<!-- ///////////////////////// -->

<script language="javascript">

  function apazHideShow ()
  {
    var state = document.getElementById('apazBox').style.visibility;
    var apazBoxState = apazGetValue ('apazBoxState');
    state = (state == 'hidden') ? 'visible' : 'hidden';
    apazSetValue ('apazBoxState', state);
    document.getElementById('apazBox').style.visibility = state;
    document.getElementById('apazMainURL1').style.visibility = state;
    document.getElementById('browseIt').style.visibility = state;
  }

  function apazPrevious ()
  {
    var apazHistoryIndex = parseInt (apazGetValue ('apazHistoryIndex'));
    if (apazHistoryIndex > 1)
    {
      apazSetValue ('apazHistoryIndex', apazHistoryIndex - 1);
      apazSetValue ('apazUseHistory', 1);
      document.forms['apazSingleForm01'].submit ();
    }
  }

  function apazNext ()
  {
    var apazHistoryIndex = parseInt (apazGetValue ('apazHistoryIndex'));
    apazSetValue ('apazHistoryIndex',  apazHistoryIndex + 1);
    apazSetValue ('apazUseHistory', 1);
    document.forms['apazSingleForm01'].submit ();
  }

  function apazRAZ ()
  {
    apazSetValue ('apazMainURL', '');
    apazSetValue ('apazCurrentURL', '');
    apazSetValue ('apazBasePath', '');
  }

  function apazSetValue (name, value)
  {
    for (var i = 0; i < document.forms.length; i++)
      eval (
        "if (document.forms[i]." + name + ") " +
        "document.forms[i]." + name + ".value = value"
      );
  }

  function apazGetValue (name)
  {
    var ret = '';
    eval ("ret = document.forms['apazSingleForm01']." + name + ".value");
    return ret;
  }

  function apazPost (url)
  {
    if (url[0] == '#')
      document.location.href = url;
    else
    {
      apazSetValue ('apazCurrentURL', url);
      document.forms['apazSingleForm01'].submit ();
    }
  }

<?php
  if (!@empty ($apaz->vars['apazCurrentURLStruct']['fragment']))
    print "document.location.href='#" . 
      $apaz->vars['apazCurrentURLStruct']['fragment'] . "';";
?>

</script>

<style>

  div#apazControl
  {
    position: <?php echo ($apaz->browserIsIE ()) ? 'absolute' : 'fixed' ?>;
    top: 3px;
    left: 3px;
    z-index: 10001;
		background: navy;
    font-weight: normal;
    text-align: center;
    padding: 1px;
  }

  div#apazControl input:hover
  {
    color: cornflowerblue;
  }

  div#apazControl input
  {
    z-index: 10001;
    font-family: Verdana,Arial,Helvetica;
    font-size: 9px;
		background: navy;
    color: white;
    text-align: center;
    font-weight: normal;
    padding: 1px;
    margin: 1px;
    border: 1px silver solid;
  }
  
  div.apazText
  {
    z-index: 10001;
    font-family: Verdana,Arial,Helvetica;
    font-size: 10px;
    font-weight: normal;
		background: gray;
    color: black;
    text-align: center;
    padding: 1px;
    margin: 1px;
    border: 1px silver solid;
  }

  div#apazBox
  {
    position: <?php echo ($apaz->browserIsIE ()) ? 'absolute' : 'fixed' ?>;
    top: 1px;
    left: 1px;
    z-index: 10000;
    font-family: Verdana,Arial,Helvetica;
    font-size: 10px;
    background: #000063;
    color: white;
    text-align: center;
    padding: 5px;
    border: 1px cornflowerblue solid;
    font-weight: bold;
  }

  div#apazBox input
  {
    font-family: Verdana,Arial,Helvetica;
    font-size: 10px;
    background: #DB8C97;
    color: black;
    border: 1px white solid;
    font-weight: bold;
  }

  div#apazBox a:link
  {
    font-family: Verdana,Arial,Helvetica;
    font-size: 10px;
    background: cornflowerblue;
		color: black;
    border: 1px solid silver;
    text-decoration: none;
    font-weight: normal;
  }

  div#apazBox a:visited
  {
    font-family: Verdana,Arial,Helvetica;
    font-size: 10px;
    background: cornflowerblue;
		color: black;
    border: 1px solid silver;
    text-decoration: none;
    font-weight: normal;
  }

  div#apazBox a:hover 
  {
    font-family: Verdana,Arial,Helvetica;
    font-size: 10px;
    background: orange;
    color: black;
    border: 1px solid white;
    text-decoration: none;
    font-weight: normal;
	}

  div#apazHelp
  {
    font-family: Verdana,Arial,Helvetica;
    font-size: 10px;
    background: black;
    color: white;
    font-weight: normal;
    border: 2px green solid;
    padding: 3px;
    text-align: justify;
  }

  div#apazHelp ul
  { 
    line-height: 1.5em;
    background: black;
    list-style-type: square;
    font-size: 10px;
    color: white;
    margin: 1.5em 0 0 1.5em;
    padding: 10px;
    list-style-image: none;
  } 

  div#apazHelp li 
  {
    margin-bottom: 1em;
  }

  div#apazWarning
  {
    font-family: Verdana,Arial,Helvetica;
    font-size: 12px;
    background: black;
    color: green;
    font-weight: bold;
    border: 1px red solid;
    padding: 3px;
    text-align: center;
  }

  div#apazWarning span {color: red;}

  div#apazWarning a:link 
  {
    background: black;
    color: yellow;
    font-weight: bold;
    font-size: 12px;
    border: 0px;
  }

  div#apazWarning a:visited 
  {
    background: black;
    color: yellow;
    font-weight: bold;
    font-size: 12px;
    border: 0px;
  }

  div#apazWarning a:hover 
  { 
    background: black;
    color: orange;
    font-weight: bold;
    font-size: 12px;
    border: 0px;
  }

</style>

<form name="apazSingleForm01" method="post" 
      action="<?php echo $apaz->vars['apazScriptURL'] ?>">

<?php echo $apaz->writeApazHiddenFields () ?>

<!-- BEGIN - aPAz Hide/Show button -->
<div id="apazControl">
  <input type="button" <?php 
         echo ($apaz->vars['apazHistoryIndex'] <= 1) ? 'disabled' : '' ?>
         title="Go to previous page" value="<" 
         onClick="apazPrevious();" />
  <input type="button" 
         title="Hide/Show the aPAz control box"
         value="aPAz" onClick="apazHideShow(); return false;"/>
  <input type="button" <?php 
      echo (!is_array ($apaz->vars['apazHistory']) || 
      $apaz->vars['apazHistoryIndex'] >= count ($apaz->vars['apazHistory'])) ?
        'disabled' : '' ?>
         title="Go to next page" value=">" onClick="apazNext();" />
</div>
<!-- END - aPAz Hide/Show button -->
<br />
<!-- BEGIN - aPAz console -->
<div id="apazBox" 
     style="visibility: <?php echo 
      htmlentities ($apaz->vars['apazBoxState']) ?>">
    <br />
    <a title="The aPAz Project Homepage" 
             target="_BLANK" 
             href="http://apaz.labs.libre-entreprise.org">A Php AnonymiZer - 
             <?php echo APP_VERSION ?></a>
    <br />
    <br />
    <input type="text" id="apazMainURL1" name="apazMainURL1" size="50" 
           style="visibility: <?php echo 
            htmlentities ($apaz->vars['apazBoxState']) ?>"
           value="<?php echo 
           $apaz->htmlentities (($apaz->vars['apazMainURL']) ? 
              $apaz->vars['apazMainURL'] : 'http://') ?>" />

    <input type="button" id="browseIt" value="Browse it" 
           style="visibility: <?php echo 
            $apaz->htmlentities ($apaz->vars['apazBoxState']) ?>"
           onClick="apazRAZ();apazSetValue('apazMainURL', apazMainURL1.value);
                    apazPost(apazMainURL1.value)" />
    <br />
<?php if ($apaz->vars['apazCurrentURL'] && !$apaz->isError ()) { ?>
    <br />
    <a target="_BLANK"
       title="Clicking on this link will browse the real URL" 
       href="<?php echo $apaz->vars['apazCurrentURL'] ?>"><?php echo 
        $apaz->htmlentities ($apaz->getShortenString ($apaz->vars['apazCurrentURL'])) ?></a>
    <br />
<?php } ?>

    <br />
    <div id="apazWarning">
      This software is still in a very early development stage.
      <br />
      &lt;.o0O&gt; <span>So please use it only for fun, 
      nothing serious for the moment</span> &lt;O0o.&gt;
      <br />
      ... and do not forget to submit <a href='http://labs.libre-entreprise.org/tracker/?atid=508&group_id=107'>bug reports</a>, <a href='http://labs.libre-entreprise.org/tracker/?atid=511&group_id=107'>feature requests</a> and <a href='http://labs.libre-entreprise.org/tracker/?atid=510&group_id=107'>patches</a>.
    </div>
    <br />
    <div id="apazHelp">

    <br />
    This is the first release of aPAz, A Php AnonymiZer.
    <br />
    <br />
    aPAz already supports HTTP protocol, HTML GET/POST forms and cookies.<br />
    Also "One Time" encryption is applied on page links. However neither<br />
    frames nor pages containing strange/complex javascript code are yet<br />
    well supported, and some Web sites will not work. 
    <br />

    Help/Tips:
    <ul>
      <li>Do not use browser history previous/next buttons. Use aPAz<br />
      controls instead.</li>
      <li>You can Hide/Show the aPAz console at any time by clicking on <br /> 
      the topleft aPAz button.</li>
      <li>To speed up page loading you can disable encryption (see aPAz<br />
      script header for details), but in this case URLs will be wrote in<br />
      Web server logs in clear.</li>
    </ul>
    </div>
</div>
</form>
<!-- END - aPAz console -->

<!-- /////////////////////// -->
<!-- END - aPAz incrustation -->
<!-- /////////////////////// -->

<?php 
  $apaz->displayEndTags ();
  $apaz->done ();
?>
