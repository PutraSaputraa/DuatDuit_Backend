<?php
// Start session PERTAMA
session_start();

// CORS Headers
header("Access-Control-Allow-Origin: https://duatduit.netlify.app");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");
header("Content-Type: application/json; charset=UTF-8");

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once 'config.php';

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

switch($action) {
    case 'register':
        register();
        break;
    case 'login':
        login();
        break;
    case 'logout':
        logout();
        break;
    case 'check':
        checkAuth();
        break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
        break;
}

// REGISTER - Daftar user baru
function register() {
    global $pdo;
    
    $data = json_decode(file_get_contents("php://input"), true);
    
    if (!isset($data['username']) || !isset($data['email']) || !isset($data['password'])) {
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

// LOGIN - Masuk ke akun
function login() {
    global $pdo;
    
    $data = json_decode(file_get_contents("php://input"), true);
    
    if (!isset($data['username']) || !isset($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Username dan password wajib diisi']);
        return;
    }
    
    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username OR email = :username");
        $stmt->execute([':username' => $data['username']]);
        $user = $stmt->fetch();
        
        if (!$user || !password_verify($data['password'], $user['password'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Username atau password salah']);
            return;
        }
        
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        
        echo json_encode([
            'success' => true,
            'message' => 'Login berhasil',
            'user' => [
                'id' => $user['id'],
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

// LOGOUT - Keluar dari akun
function logout() {
    session_destroy();
    
    echo json_encode([
        'success' => true,
        'message' => 'Logout berhasil'
    ]);
}

// CHECK AUTH - Cek apakah user sudah login
function checkAuth() {
    if (isset($_SESSION['user_id'])) {
        echo json_encode([
            'success' => true,
            'authenticated' => true,
            'user' => [
                'id' => $_SESSION['user_id'],
                'username' => $_SESSION['username']
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
