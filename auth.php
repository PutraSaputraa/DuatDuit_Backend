<?php
// ==========================================
// FILE: auth.php - LOGIN & REGISTER
// ==========================================

// ✅ CORS HEADERS (pastikan ini ada di .htaccess atau di sini)
header("Access-Control-Allow-Origin: *"); // Atau ganti dengan domain Netlify Anda
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once 'config.php';

// ✅ SECRET KEY untuk JWT (GANTI dengan key rahasia Anda sendiri!)
define('JWT_SECRET_KEY', 'ganti-dengan-key-rahasia-anda-123456');
define('JWT_ALGORITHM', 'HS256');

// ✅ Fungsi untuk generate JWT Token
function generateJWT($user_id, $username) {
    $header = json_encode(['typ' => 'JWT', 'alg' => JWT_ALGORITHM]);
    $payload = json_encode([
        'user_id' => $user_id,
        'username' => $username,
        'exp' => time() + (7 * 24 * 60 * 60) // Token valid 7 hari
    ]);

    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, JWT_SECRET_KEY, true);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
}

// ✅ Fungsi untuk verify JWT Token
function verifyJWT($token) {
    $tokenParts = explode('.', $token);
    if (count($tokenParts) !== 3) {
        return false;
    }

    list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = $tokenParts;
    
    $signature = str_replace(['-', '_'], ['+', '/'], $base64UrlSignature);
    $expectedSignature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, JWT_SECRET_KEY, true);
    $expectedBase64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($expectedSignature));
    
    if ($base64UrlSignature !== $expectedBase64UrlSignature) {
        return false;
    }

    $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $base64UrlPayload)), true);
    
    // Cek apakah token expired
    if (isset($payload['exp']) && $payload['exp'] < time()) {
        return false;
    }

    return $payload;
}

$action = $_GET['action'] ?? '';

switch($action) {
    case 'register': register(); break;
    case 'login':    login();    break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
        break;
}

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
        
        // ✅ Generate JWT Token
        $token = generateJWT($user['id'], $user['username']);
        
        echo json_encode([
            'success' => true,
            'message' => 'Login berhasil',
            'token' => $token, // ✅ KIRIM TOKEN KE FRONTEND
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
?>