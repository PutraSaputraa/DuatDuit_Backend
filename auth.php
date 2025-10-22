<?php
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once 'config.php';

// Secret key untuk JWT (ganti dengan string random yang kuat)
define('JWT_SECRET', 'ganti_dengan_secret_key_yang_aman_12345');

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

switch($action) {
    case 'register': register(); break;
    case 'login':    login();    break;
    case 'logout':   logout();   break;
    case 'check':    checkAuth(); break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
        break;
}

// Fungsi untuk membuat JWT Token sederhana
function createJWT($userId, $username) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload = json_encode([
        'user_id' => $userId,
        'username' => $username,
        'exp' => time() + (86400 * 7) // Token berlaku 7 hari
    ]);
    
    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, JWT_SECRET, true);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
}

// Fungsi untuk verifikasi JWT Token
function verifyJWT($token) {
    if (!$token) return null;
    
    $tokenParts = explode('.', $token);
    if (count($tokenParts) !== 3) return null;
    
    $header = base64_decode(str_replace(['-', '_'], ['+', '/'], $tokenParts[0]));
    $payload = base64_decode(str_replace(['-', '_'], ['+', '/'], $tokenParts[1]));
    $signatureProvided = $tokenParts[2];
    
    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, JWT_SECRET, true);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    if ($base64UrlSignature !== $signatureProvided) return null;
    
    $payloadData = json_decode($payload, true);
    
    // Cek apakah token expired
    if (isset($payloadData['exp']) && $payloadData['exp'] < time()) {
        return null;
    }
    
    return $payloadData;
}

// Fungsi untuk mendapatkan token dari header
function getBearerToken() {
    $headers = getallheaders();
    
    if (isset($headers['Authorization'])) {
        if (preg_match('/Bearer\s+(.*)$/i', $headers['Authorization'], $matches)) {
            return $matches[1];
        }
    }
    
    return null;
}

// REGISTER
function register() {
    global $pdo;
    
    $data = json_decode(file_get_contents("php://input"), true);
    
    if (!isset($data['username'], $data['email'], $data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Username, email, dan password wajib diisi']);
        return;
    }
    
    if (strlen($data['password']) < 6) {
        http_response_code(400);
        echo json_encode(['error' => 'Password minimal 6 karakter']);
        return;
    }
    
    try {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username OR email = :email");
        $stmt->execute([
            ':username' => $data['username'],
            ':email' => $data['email']
        ]);
        
        if ($stmt->fetch()) {
            http_response_code(400);
            echo json_encode(['error' => 'Username atau email sudah terdaftar']);
            return;
        }
        
        $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
        
        $stmt = $pdo->prepare("
            INSERT INTO users (username, email, password, full_name) 
            VALUES (:username, :email, :password, :full_name)
        ");
        
        $stmt->execute([
            ':username' => $data['username'],
            ':email' => $data['email'],
            ':password' => $hashedPassword,
            ':full_name' => $data['full_name'] ?? ''
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Registrasi berhasil! Silakan login.'
        ]);
        
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// LOGIN
function login() {
    global $pdo;
    
    $data = json_decode(file_get_contents("php://input"), true);
    
    if (!isset($data['username'], $data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Username dan password wajib diisi']);
        return;
    }
    
    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :user OR email = :email");
        $stmt->execute([
            ':user' => $data['username'],
            ':email' => $data['username']
        ]);
        $user = $stmt->fetch();
        
        if (!$user || !password_verify($data['password'], $user['password'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Username atau password salah']);
            return;
        }
        
        // Buat JWT Token
        $token = createJWT($user['id'], $user['username']);
        
        echo json_encode([
            'success' => true,
            'message' => 'Login berhasil',
            'token' => $token,
            'user' => [
                'id' => (int)$user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'full_name' => $user['full_name']
            ]
        ]);
        
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// LOGOUT
function logout() {
    echo json_encode([
        'success' => true,
        'message' => 'Logout berhasil'
    ]);
}

// CHECK AUTH
function checkAuth() {
    $token = getBearerToken();
    
    if (!$token) {
        echo json_encode([
            'success' => true,
            'authenticated' => false
        ]);
        return;
    }
    
    $payload = verifyJWT($token);
    
    if ($payload) {
        echo json_encode([
            'success' => true,
            'authenticated' => true,
            'user' => [
                'id' => $payload['user_id'],
                'username' => $payload['username']
            ]
        ]);
    } else {
        echo json_encode([
            'success' => true,
            'authenticated' => false
        ]);
    }
}
?>