<?php
// ✅ PENTING: Set CORS headers sebelum session_start()
header("Access-Control-Allow-Origin: http://localhost:3000"); // Ganti dengan domain frontend Anda
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=UTF-8");

// Handle preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ✅ Start session SETELAH CORS headers
session_start();

require_once 'config.php';

// Fungsi untuk cek apakah user sudah login
function checkAuth() {
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized. Please login first.']);
        exit();
    }
    
    return $_SESSION['user_id'];
}

$method = $_SERVER['REQUEST_METHOD'];

switch($method) {
    case 'GET':
        $user_id = checkAuth();
        getTransactions($user_id);
        break;
    case 'POST':
        $user_id = checkAuth();
        addTransaction($user_id);
        break;
    case 'DELETE':
        $user_id = checkAuth();
        deleteTransaction($user_id);
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

// GET - Ambil transaksi user yang login saja
function getTransactions($user_id) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("SELECT * FROM transactions WHERE user_id = :user_id ORDER BY date DESC, created_at DESC");
        $stmt->execute([':user_id' => $user_id]);
        $transactions = $stmt->fetchAll();
        
        echo json_encode([
            'success' => true,
            'data' => $transactions
        ]);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// POST - Tambah transaksi untuk user yang login
function addTransaction($user_id) {
    global $pdo;
    
    $data = json_decode(file_get_contents("php://input"), true);
    
    if (!isset($data['type']) || !isset($data['amount']) || !isset($data['category']) || 
        !isset($data['source']) || !isset($data['date'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields']);
        return;
    }
    
    try {
        $stmt = $pdo->prepare("
            INSERT INTO transactions (user_id, type, amount, category, source, description, date) 
            VALUES (:user_id, :type, :amount, :category, :source, :description, :date)
        ");
        
        $stmt->execute([
            ':user_id' => $user_id,
            ':type' => $data['type'],
            ':amount' => $data['amount'],
            ':category' => $data['category'],
            ':source' => $data['source'],
            ':description' => $data['description'] ?? '',
            ':date' => $data['date']
        ]);
        
        $newId = $pdo->lastInsertId();
        
        echo json_encode([
            'success' => true,
            'id' => $newId,
            'message' => 'Transaction added successfully'
        ]);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// DELETE - Hapus transaksi milik user yang login
function deleteTransaction($user_id) {
    global $pdo;
    
    $data = json_decode(file_get_contents("php://input"), true);
    
    if (!isset($data['id'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Transaction ID required']);
        return;
    }
    
    try {
        $stmt = $pdo->prepare("DELETE FROM transactions WHERE id = :id AND user_id = :user_id");
        $stmt->execute([
            ':id' => $data['id'],
            ':user_id' => $user_id
        ]);
        
        if ($stmt->rowCount() > 0) {
            echo json_encode([
                'success' => true,
                'message' => 'Transaction deleted successfully'
            ]);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Transaction not found or unauthorized']);
        }
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

?>