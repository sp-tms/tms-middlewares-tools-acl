<?php

namespace Apps\Tms\Middlewares\Acl\Install;

use System\Base\BasePackage;

class Install extends BasePackage
{
    public function install()
    {
        return true;
    }

    public function uninstall()
    {
        return true;
    }
}