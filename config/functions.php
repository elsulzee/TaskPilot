<?php 
function clean_input($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

function respond($status, $message, $data = null) {
    $response = [
        "status" => $status,
        "message" => $message
    ];

    if (!is_null($data)) {
        $response["data"] = $data;
    }

    echo json_encode($response);
    exit;
}

?>