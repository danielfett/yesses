<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;

class TestController extends Controller
{

    public function show($param)
    {	
        return "<h1>Hello World!</h1></br><p>".$param."</p>";
    }
}
