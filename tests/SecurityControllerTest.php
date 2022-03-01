<?php

namespace App\Tests;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;


class SecurityControllerTest extends WebTestCase
{

    public function testShowLogin()
    {
        $client = static::createClient();


        $client->request('GET', '/login');

        //HTTP_OK -> renvoie la valeur 200 si le site est ok
        $this->assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());

        //affirme que le selecteur de texte contient 'Log In'
        $this->assertSelectorTextContains('html head title', 'Log in!');
    }


    private function logIn($userName = 'user', $useRole = 'ROLE_USER')
    {
        $client = static::createClient();

        $session = $client->getContainer()->get('session');

        $firewallName = 'main';
        // if you don't define multiple connected firewalls, the context defaults to the firewall name
        // See https://symfony.com/doc/current/reference/configuration/security.html#firewall-context
        $firewallContext = 'main';

        // you may need to use a different token class depending on your application.
        // for example, when using Guard authentication you must instantiate PostAuthenticationGuardToken
        $token = new UsernamePasswordToken('admin', null, $firewallName, ['ROLE_ADMIN']);
        $session->set('_security_'.$firewallContext, serialize($token));
        $session->save();

        $cookie = new Cookie($session->getName(), $session->getId());
        $client->getCookieJar()->set($cookie);
    }

    public function testSecuredRoleUser()
    {
        $this->logIn('user', 'ROLE_USER');
        $crawler = $client->request('GET', '/category/');

        $this->assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());
        $this->assertEquals('Category index', $crawler->filter('h1')->text());

    }
    }

