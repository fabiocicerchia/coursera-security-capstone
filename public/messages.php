<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/inc/config.php';
require_once __DIR__ . '/../src/inc/database.php';
require_once __DIR__ . '/../src/inc/php_security.php';

session_name('CSCSI'); // Coursera Security Capstone Session Id
session_start();
session_regenerate_id();

$usernameEnc = $_SESSION['user'];

if (empty($usernameEnc)) {
    header('Location: /login.php');
    exit;
}

$iv = hash(HASH_ALGORITHM, GLOBAL_ENC_KEY, false);

$stmt = $dbh->prepare('SELECT id, username, key_pub, key_priv FROM users WHERE username = :username LIMIT 1');
$stmt->execute([':username' => $usernameEnc]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
$stmt = null;

if (empty($row)) {
    header('HTTP/1.1 401 Unauthorized');
    exit;
}

$userFromId = $row['id'];
$username = $row['username'];
$privKey = openssl_get_privatekey(openssl_decrypt($row['key_priv'], CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv));
$pubKey = openssl_get_publickey(openssl_decrypt($row['key_pub'], CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv));

if (!empty($_POST)) {
    $action = $_POST['action'];
    if ($action === 'new') {
        $message = $_POST['body'];
        $to = $_POST['to'];

        $usernameToEnc = openssl_encrypt($to, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

        $stmt = $dbh->prepare('SELECT id, key_pub FROM users WHERE username = :username LIMIT 1');
        $stmt->execute([':username' => $usernameToEnc]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt = null;
        $userToId = $row['id'];
        $pubKeyTo = openssl_get_publickey(openssl_decrypt($row['key_pub'], CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv));

        if ($userToId) {
            openssl_public_encrypt($message, $messageEnc, $pubKey, OPENSSL_PKCS1_OAEP_PADDING);
            $stmt = $dbh->prepare("INSERT INTO messages (user_id, user_from, user_to, message, date) VALUES (?, ?, ?, ?, current_timestamp);");
            $stmt->execute([$userFromId, $userFromId, $userToId, base64_encode($messageEnc)]);
            $stmt = null;
            
            openssl_public_encrypt($message, $messageEnc, $pubKeyTo, OPENSSL_PKCS1_OAEP_PADDING);
            $stmt = $dbh->prepare("INSERT INTO messages (user_id, user_from, user_to, message, date) VALUES (?, ?, ?, ?, current_timestamp);");
            $stmt->execute([$userToId, $userFromId, $userToId, base64_encode($messageEnc)]);
            $stmt = null;
        } else {} // TODO: no user available
    }
}

// messages
$stmt = $dbh->prepare('SELECT users.username, users.hash, messages.user_id AS from, users.id AS to, SUM(CASE WHEN messages.user_id = messages.user_to AND messages.read = false THEN 1 ELSE 0 END) AS new FROM messages INNER JOIN users ON (users.id = messages.user_to OR users.id = messages.user_from) WHERE messages.user_id = :user GROUP BY users.username, users.hash, messages.user_id, users.id');
$stmt->execute([':user' => $userFromId]);
$recipients = $stmt->fetchAll(PDO::FETCH_ASSOC);

$messages = [];

if (!empty($_GET['to'])) {
    $to = $_GET['to'];
    $stmt = $dbh->prepare('SELECT messages.* FROM messages INNER JOIN users ON (messages.user_to = users.id OR messages.user_from = users.id) WHERE messages.user_id = :user AND users.hash = :to ORDER BY messages.date ASC');
    $stmt->execute([':user' => $userFromId, ':to' => $to]);
    $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $dbh->prepare('SELECT id, username FROM users WHERE hash = :username LIMIT 1');
    $stmt->execute([':username' => $to]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt = null;
    $to = $row['username'];

    $stmt = $dbh->prepare('UPDATE messages SET read = true WHERE user_id = :user AND (user_to = :to OR user_from = :to)');
    $stmt->execute([':user' => $userFromId, ':to' => $row['id']]);
    $stmt = null;
}

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css" type="text/css" rel="stylesheet" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>">
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>"></script>
    <style type="text/css" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>">
    .container{max-width:1170px; margin:auto;}
    img{ max-width:100%;}
    .inbox_people {
      background: #f8f8f8 none repeat scroll 0 0;
      float: left;
      overflow: hidden;
      width: 40%; border-right:1px solid #c4c4c4;
    }
    .inbox_msg {
      border: 1px solid #c4c4c4;
      clear: both;
      overflow: hidden;
    }
    .top_spac{ margin: 20px 0 0;}
    
    
    .recent_heading {float: left; width:40%;}
    .srch_bar {
      display: inline-block;
      text-align: right;
      width: 60%; padding:
    }
    .headind_srch{ padding:10px 29px 10px 20px; overflow:hidden; border-bottom:1px solid #c4c4c4;}
    
    .recent_heading h4 {
      color: #05728f;
      font-size: 21px;
      margin: auto;
    }
    .srch_bar input{ border:1px solid #cdcdcd; border-width:0 0 1px 0; width:80%; padding:2px 0 4px 6px; background:none;}
    .srch_bar .input-group-addon button {
      background: rgba(0, 0, 0, 0) none repeat scroll 0 0;
      border: medium none;
      padding: 0;
      color: #707070;
      font-size: 18px;
    }
    .srch_bar .input-group-addon { margin: 0 0 0 -27px;}
    
    .chat_ib h5{ font-size:15px; color:#464646; margin:0 0 8px 0;}
    .chat_ib h5 span{ font-size:13px; float:right;}
    .chat_ib p{ font-size:14px; color:#989898; margin:auto}
    .chat_img {
      float: left;
      width: 11%;
    }
    .chat_ib {
      float: left;
      padding: 0 0 0 15px;
      width: 88%;
    }
    
    .chat_people{ overflow:hidden; clear:both;}
    .chat_list {
      border-bottom: 1px solid #c4c4c4;
      margin: 0;
      padding: 18px 16px 10px;
    }
    .inbox_chat { height: 550px; overflow-y: scroll;}
    
    .active_chat{ background:#ebebeb;}
    
    .incoming_msg_img {
      display: inline-block;
      width: 6%;
    }
    .received_msg {
      display: inline-block;
      padding: 0 0 0 10px;
      vertical-align: top;
      width: 92%;
     }
     .received_withd_msg p {
      background: #ebebeb none repeat scroll 0 0;
      border-radius: 3px;
      color: #646464;
      font-size: 14px;
      margin: 0;
      padding: 5px 10px 5px 12px;
      width: 100%;
    }
    .time_date {
      color: #747474;
      display: block;
      font-size: 12px;
      margin: 8px 0 0;
    }
    .received_withd_msg { width: 57%;}
    .mesgs {
      float: left;
      padding: 30px 15px 0 25px;
      width: 60%;
    }
    
     .sent_msg p {
      background: #05728f none repeat scroll 0 0;
      border-radius: 3px;
      font-size: 14px;
      margin: 0; color:#fff;
      padding: 5px 10px 5px 12px;
      width:100%;
    }
    .outgoing_msg{ overflow:hidden; margin:26px 0 26px;}
    .sent_msg {
      float: right;
      width: 46%;
    }
    .input_msg_write input {
      background: rgba(0, 0, 0, 0) none repeat scroll 0 0;
      border: medium none;
      color: #4c4c4c;
      font-size: 15px;
      min-height: 48px;
      width: 100%;
    }
    
    .type_msg {border-top: 1px solid #c4c4c4;position: relative;}
    .msg_send_btn {
      background: #05728f none repeat scroll 0 0;
      border: medium none;
      border-radius: 50%;
      color: #fff;
      cursor: pointer;
      font-size: 17px;
      height: 33px;
      position: absolute;
      right: 0;
      top: 11px;
      width: 33px;
    }
    .messaging { padding: 0 0 50px 0;}
    .msg_history {
      height: 516px;
      overflow-y: auto;
    }
    </style>
    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>"></script>
    <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>"></script>
</head>
<body>
<div class="container">
<h3 class=" text-center">Messaging (<?php echo htmlspecialchars(openssl_decrypt($username, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv)); ?>)</h3>


<div class="messaging">
      <div class="inbox_msg">
        <div class="inbox_people">
          <div class="headind_srch">
            <div class="recent_heading">
              <h4>Messages</h4>
            </div>
            <button type="button" class="btn btn-secondary pull-right btn-sm" data-toggle="modal" data-target="#exampleModal">New message</button>
          </div>
          <div class="inbox_chat">
            <?php foreach ($recipients as $idx => $recipient): ?>
            <?php if ($recipient['from'] !== $recipient['to']): ?>
        <div class="chat_list<?php if ($recipient['username'] === $to): ?> active_chat<?php endif; ?>">
              <div class="chat_people">
                <div class="chat_img"> <img src="/user-profile.png"> </div>
                <div class="chat_ib">
		    <h5><a href="/messages.php?to=<?php echo rawurlencode(htmlspecialchars($recipient['hash'])); ?>"><?php echo openssl_decrypt($recipient['username'], CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv); ?></a></h5>
		    <?php if ($recipient['new'] > 0): ?><span class="badge badge-info">New Messages <span class="badge badge-light"><?php echo htmlspecialchars($recipient['new']); ?></span></span><?php endif; ?>
                </div>
              </div>
            </div>
            <?php endif; ?>
            <?php endforeach; ?>
          </div>
        </div>
        <div class="mesgs">
          <div class="msg_history">
            <?php foreach ($messages as $message): ?>
	    <?php if ($message['user_id'] === $message['user_to']): ?>
            <div class="incoming_msg">
              <div class="incoming_msg_img"> <img src="/user-profile.png"> </div>
              <div class="received_msg">
                <div class="received_withd_msg">
		  <p><?php openssl_private_decrypt(base64_decode($message['message']), $messageDec, $privKey, OPENSSL_PKCS1_OAEP_PADDING); echo htmlspecialchars($messageDec); ?></p>
		  <span class="time_date"><?php echo htmlspecialchars(date('H:i | M j', strtotime($message['date']))); ?></span></div>
              </div>
            </div>
	    <?php else: ?>
            <div class="outgoing_msg">
              <div class="sent_msg">
		<p><?php openssl_private_decrypt(base64_decode($message['message']), $messageDec, $privKey, OPENSSL_PKCS1_OAEP_PADDING); echo htmlspecialchars($messageDec); ?></p>
	        <span class="time_date"><?php echo htmlspecialchars(date('H:i | M j', strtotime($message['date']))); ?></span></div>
            </div>
            <?php endif; ?>
            <?php endforeach; ?>
          </div>
	  <?php if (!empty($to)): ?>
          <div class="type_msg">
            <div class="input_msg_write">
              <form method="post">
              <input type="hidden" name="action" value="new">
	      <input type="hidden" name="to" value="<?php echo htmlspecialchars(openssl_decrypt($to, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv)); ?>">
              <input type="text" class="write_msg" name="body" placeholder="Type a message" />
              <button class="msg_send_btn" type="submit"><i class="fa fa-paper-plane-o" aria-hidden="true"></i></button>
              </form>
            </div>
          </div>
          <?php endif; ?>
        </div>
      </div>
      
    </div></div>
    <div class="modal fade" id="exampleModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
      <div class="modal-dialog" role="document">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="exampleModalLabel">New message</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body">
            <form method="post" id="newmsg">
              <input type="hidden" name="action" value="new">
              <div class="form-group">
                <label for="recipient-name" class="col-form-label">Recipient:</label>
                <input type="text" name="to" class="form-control" id="recipient-name">
              </div>
              <div class="form-group">
                <label for="message-text" class="col-form-label">Message:</label>
                <textarea class="form-control" name="body" id="message-text"></textarea>
              </div>
            </form>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
            <button type="submit" class="btn btn-primary">Send message</button>
          </div>
        </div>
      </div>
    </div>
<a href="/logout.php" class="pull-right btn btn-light mb-3 mr-3">Logout</a>
        <script nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>">
            $('#exampleModal .btn-primary').click(function() { $('#newmsg').submit(); });
            var objDiv = document.querySelector('.msg_history');
	    objDiv.scrollTop = objDiv.scrollHeight;
        </script>
    </body>
</html>
