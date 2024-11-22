<?php
session_start();
include "db_connect.php";

// Get purchase details from URL or POST data
$user_id = $_SESSION['user_id']; // Assuming user is logged in
$game_name = $_GET['game']; // Get the game name from the URL
$item_name = $_GET['item']; // Get the item purchased
$amount = $_GET['amount']; // Get the amount of the item purchased
$promo_code = isset($_GET['promoCode']) ? $_GET['promoCode'] : NULL; // Get promo code used (if any)
$price = $_GET['price']; // Get total price from the URL

// Initialize additional fields for game-specific data
$server_id = $riot_username = $player_id = $riot_id = $character_id = $player_tag = $open_id = NULL;

// Set game-specific data
switch ($game_name) {
    case 'PUBG Mobile':
        $player_id = isset($_GET['playerId']) ? $_GET['playerId'] : NULL; // Get player ID for PUBG
        break;

    case 'Mobile Legends':
    case 'Genshin Impact':
        $server_id = isset($_GET['serverId']) ? $_GET['serverId'] : NULL; // Get server ID
        break;

    case 'Valorant':
        $riot_username = isset($_GET['riotUsername']) ? $_GET['riotUsername'] : NULL; // Get Riot username
        break;

    case 'Call of Duty: Mobile':
        $open_id = isset($_GET['openId']) ? $_GET['openId'] : NULL; // Get Open ID
        break;

    case 'Sausage Man':
        $character_id = isset($_GET['characterId']) ? $_GET['characterId'] : NULL; // Get Character ID
        break;

    case 'Honor of Kings':
        $player_id = isset($_GET['playerId']) ? $_GET['playerId'] : NULL; // Get Player ID
        break;

    case 'Wild Rift':
        $riot_id = isset($_GET['riotId']) ? $_GET['riotId'] : NULL; // Get Riot ID
        break;

    case 'E-Football':
        $email = isset($_GET['email']) ? $_GET['email'] : NULL; // Get email address
        break;

    case 'Super SUS':
        $user_id = isset($_GET['userId']) ? $_GET['userId'] : NULL; // Get User ID for Super SUS
        break;

    default:
        // No specific data for unknown games
        break;
}

// Prepare SQL query to insert purchase into the database
$query = "INSERT INTO purchases (user_id, game_name, item_name, amount, promo_code, price, server_id, riot_username, player_id, riot_id, character_id, player_tag, open_id) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
$stmt = $conn->prepare($query);

// Bind parameters: ensure correct data types are used (i = integer, d = decimal, s = string)
$stmt->bind_param("issdssssssss", $user_id, $game_name, $item_name, $amount, $promo_code, $price, $server_id, $riot_username, $player_id, $riot_id, $character_id, $player_tag, $open_id);

// Execute the query
$stmt->execute();

// Redirect to the receipt page
header("Location: receipt.php?orderId=" . $stmt->insert_id . "&game=" . urlencode($game_name) . "&item=" . urlencode($item_name) . "&amount=" . $amount . "&promoCode=" . urlencode($promo_code) . "&price=" . $price);
exit();
?>
