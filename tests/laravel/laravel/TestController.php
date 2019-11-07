<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;

class TestController extends Controller
{

    public function show($param)
    {
        $ip = "172.45.0.12"
        $email = "test@laravel.dev.intranet"
        return "<h1>Hello World!</h1></br><p>".$param."</p>";
    }
}
