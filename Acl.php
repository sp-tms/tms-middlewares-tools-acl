<?php

namespace Apps\Tms\Middlewares\Acl;

use Phalcon\Acl\Component;
use Phalcon\Acl\Role;
use System\Base\BaseMiddleware;
use System\Base\Providers\AccessServiceProvider\Exceptions\PermissionDeniedException;

class Acl extends BaseMiddleware
{
    protected $components = [];

    protected $controller;

    protected $actions;

    protected $action;

    protected $account;

    protected $accountEmail;

    protected $role;

    protected $accountPermissions;

    protected $found = false;

    protected $isApi = false;

    protected $isApiPublic = false;

    public function process($data)
    {
        $this->isApi = $this->api->isApi();
        if ($this->api->isApiCheckVia && $this->api->isApiCheckVia === 'pub') {
            $this->isApiPublic = true;
        }

        $this->actions =
            ['view', 'add', 'update', 'remove', 'msview', 'msupdate', 'activitylogs'];

        $rolesArr = $this->basepackages->roles->getAll()->roles;
        $roles = [];
        foreach ($rolesArr as $key => $value) {
            $roles[$value['id']] = $value;
        }

        $this->checkCachePath();
        $aclFileDir =
            'var/storage/cache/' .
            $this->app['app_type'] . '/' .
            $this->app['route'] . '/acls/';
        if (!$this->setControllerAndAction()) {
            return true;
        }

        if ($this->isApi) {
            $this->role = $this->api->getScope();
        } else {
            $this->account = $this->access->auth->account();
        }

        if ($this->account) {
            if (is_string($this->account['security']['permissions'])) {
                $this->account['security']['permissions'] = $this->helper->decode($this->account['security']['permissions'], true);
            }

            $this->accountPermissions = $this->account['security']['permissions'];

            //System Admin bypasses the ACL if they don't have any permissions defined.
            if ($this->account['id'] == '1' &&
                $this->account['security']['role_id'] == '1' &&
                count($this->accountPermissions) === 0
            ) {
                return;
            }

            $this->role = $roles[$this->account['security']['role_id']];

            if (is_string($this->role['permissions'])) {
                $this->role['permissions'] = $this->helper->decode($this->role['permissions'], true);
            }

            if ($this->account['security']['override_role'] == '1') {
                if (count($this->accountPermissions) === 0) {
                    throw new PermissionDeniedException();
                }

                $this->accountEmail = str_replace('.', '', str_replace('@', '', $this->account['email']));

                if ($this->localContent->fileExists($aclFileDir . $this->accountEmail . $this->account['id'])) {

                    $this->access->acl = unserialize($this->localContent->read($aclFileDir . $this->accountEmail . $this->account['id']));
                } else {
                    $this->access->acl->addRole(
                        new Role($this->accountEmail, 'User Override Role')
                    );

                    $this->generateComponentsArr();

                    foreach ($this->accountPermissions as $appKey => $app) {
                        foreach ($app as $componentKey => $permission) {
                            if ($this->app['id'] == $appKey) {
                                if ($this->components[$componentKey]['route'] === $this->controllerRoute) {
                                    $this->buildAndTestAcl($this->accountEmail, $componentKey, $permission);
                                    break 2;
                                }
                            }
                        }
                    }

                    if ($this->config->cache->enabled) {
                        $this->localContent->write($aclFileDir . $this->accountEmail . $this->account['id'], serialize($this->access->acl));
                    }
                }

                if (!$this->access->acl->isAllowed($this->accountEmail, $this->controllerRoute, $this->action)) {
                    throw new PermissionDeniedException();
                }

                return;
            } else if (count($this->role['permissions']) === 0) {
                throw new PermissionDeniedException();
            }
        } else {
            if (!$this->role) {
                $this->role = $roles[$this->app['guest_role_id']];
            }
        }

        $this->roleName = strtolower(str_replace(' ', '', $this->role['name']));

        if ($this->localContent->fileExists(
                    $aclFileDir . $this->roleName . $this->role['id'] . $this->controllerRoute . $this->action
                )
        ) {
            $this->access->acl =
                unserialize(
                    $this->localContent->read(
                        $aclFileDir . $this->roleName . $this->role['id'] . $this->controllerRoute . $this->action
                    )
                );
        } else {
            $this->generateComponentsArr();

            $this->access->acl->addRole(
                new Role($this->roleName, $this->role['description'])
            );

            if (is_string($this->role['permissions'])) {
                $this->role['permissions'] = $this->helper->decode($this->role['permissions'], true);
            }

            foreach ($this->role['permissions'] as $appKey => $app) {
                foreach ($app as $componentKey => $permission) {
                    if ($this->app['id'] == $appKey) {
                        if (isset($this->components[$componentKey]) &&
                            $this->components[$componentKey]['route'] === $this->controllerRoute
                        ) {
                            if (($this->isApi && $this->helper->has($this->components[$componentKey]['api_acls'], $this->action)) ||
                                (!$this->isApi && $this->helper->has($this->components[$componentKey]['acls'], $this->action))
                            ) {
                                $this->found = true;
                                $this->buildAndTestAcl($this->roleName, $componentKey, $permission);
                                break 2;
                            }
                        }
                    }
                }
            }

            if ($this->config->cache->enabled) {
                $this->localContent->write(
                    $aclFileDir . $this->roleName . $this->role['id'] . $this->controllerRoute . $this->action, serialize($this->access->acl)
                );
            }
        }

        if ($this->found &&
            !$this->access->acl->isAllowed($this->roleName, $this->controllerRoute, $this->action)
        ) {
            throw new PermissionDeniedException();
        }
    }

    protected function setControllerAndAction()
    {
        if ($this->isApi) {
            $controllerName = $this->router->getControllerName();
        } else {
            $controllerName = $this->dispatcher->getControllerName();
        }

        $component =
            $this->modules->components->getComponentByClassForAppId(
                $controllerName,
                $this->app['id']
            );
        if (!$component) {
            if ($this->apps->isMurl) {
                $url = explode('/', trim(explode('/q/', $this->apps->isMurl['url'])[0], '/'));
            } else {
                $url = explode('/', trim(explode('/q/', $this->request->getUri())[0], '/'));
            }

            if ($this->request->isPost()) {
                unset($url[$this->helper->lastKey($url)]);
            }

            if (isset($this->domains->domain['exclusive_to_default_app']) &&
                $this->domains->domain['exclusive_to_default_app'] == 0 &&
                $url[0] === $this->apps->getAppInfo()['route']
            ) {
                unset($url[0]);
            }

            $componentRoute = implode('/', $url);
            $component =
                $this->modules->components->getComponentByRouteForAppId(
                    strtolower($componentRoute), $this->app['id']
                );

            if (!$component) {
                return false;
            }
        }

        $this->controllerRoute = $component['route'];

        if ($this->isApi) {
            $action = $this->router->getActionName();
        } else {
            $action = strtolower(str_replace('Action', '', $this->dispatcher->getActiveMethod()));
        }

        if (!in_array($action, $this->actions)) {
            return false;
        }

        $this->action = $action;

        return true;
    }

    protected function buildAndTestAcl($roleName, $componentKey, $permission, $fullAccess = null)
    {
        $componentRoute = $this->components[$componentKey]['route'];
        $componentDescription = $this->components[$componentKey]['description'];
        $componentAcls = $this->components[$componentKey]['acls'];
        if ($this->isApi && isset($this->components[$componentKey]['api_acls'])) {
            $componentAcls = $this->components[$componentKey]['api_acls'];
        }

        $this->access->acl->addComponent(
            new Component($componentRoute, $componentDescription), $componentAcls
        );

        if ($permission[$this->action] === 1) {
            $this->access->acl->allow($roleName, $componentRoute, $this->action);
            $this->logger->log->debug(
                'User ' . $this->accountEmail . ' granted access to component ' . $componentRoute . ' for action ' . $this->action
            );
        } else {
            $this->logger->log->debug(
                'User ' . $this->accountEmail . ' denied access to component ' . $componentRoute . ' for action ' . $this->action
            );
        }
    }

    protected function checkCachePath()
    {
        if (
            !is_dir(
                base_path(
                    'var/storage/cache/' .
                    $this->domains->getDomain()['name'] . '/' .
                    $this->app['route'] . '/acls/'
                )
            )
        ) {
            if (
                !mkdir(
                    base_path(
                        'var/storage/cache/' .
                        $this->domains->getDomain()['name'] . '/' .
                        $this->app['route'] . '/acls/'
                    ), 0777, true
                )
            ) {
                return false;
            }
        }
        return true;
    }

    protected function generateComponentsArr()
    {
        $componentsArr = $this->modules->components->components;

        foreach ($componentsArr as $component) {
            if ($component['class'] && $component['class'] !== '') {
                $reflector = $this->annotations->get($component['class']);
                $methods = $reflector->getMethodsAnnotations();

                if ($methods && count($methods) > 2) {
                    if (isset($methods['viewAction'])) {
                        $this->components[$component['id']]['name'] = strtolower($component['name']);
                        $this->components[$component['id']]['route'] = strtolower($component['route']);
                        $this->components[$component['id']]['description'] = $component['description'];
                        foreach ($methods as $annotation) {
                            if ($annotation->getAll('acl')) {
                                $action = $annotation->getAll('acl')[0]->getArguments();
                                $this->components[$component['id']]['acls'][$action['name']] = $action['name'];
                            } else if ($annotation->getAll('api_acl')) {
                                $action = $annotation->getAll('api_acl')[0]->getArguments();
                                $this->components[$component['id']]['api_acls'][$action['name']] = $action['name'];
                            }
                        }
                    }
                }
            }
        }
    }
}
