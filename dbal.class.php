<?php
namespace OAuth2\Storage;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
/**
 * Simple DBAL storage for all storage types
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class DBAL implements
    AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface,
    PublicKeyInterface,
    UserClaimsInterface,
    OpenIDAuthorizationCodeInterface
{
    protected $db;
    protected $config;
    public function __construct($connection, $config = array())
    {
        $this->db = $connection;
        $this->config = array_merge(array(
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table'  => 'oauth_jwt',
            'jti_table'  => 'oauth_jti',
            'scope_table'  => 'oauth_scopes',
            'public_key_table'  => 'oauth_public_keys',
        ), $config);
    }
 
    /* OAuth2\Storage\ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $result = $this->db->fetchAssoc(sprintf('SELECT * from %s where client_id = ?', $this->config['client_table'])
            , array($client_id));
        return $result && $result['client_secret'] == $client_secret;
    }
    public function isPublicClient($client_id)
    {
        $result = $this->db->fetchAssoc(sprintf('SELECT * from %s where client_id = ?', $this->config['client_table']),
            array($client_id));
        if (!$result) {
            return false;
        }
        return empty($result['client_secret']);
    }
    /* OAuth2\Storage\ClientInterface */
    public function getClientDetails($client_id)
    {
        $result = $this->db->fetchAssoc(sprintf('SELECT * from %s where client_id = ?', $this->config['client_table']),
            array($client_id));
        return $result;
    }
    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        $client = array(
            'client_secret' => $client_secret,
            'redirect_uri' => $redirect_uri,
            'grant_types' => $grant_types,
            'scope' => $scope,
            'user_id' => $user_id
        );

        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
            $result = $this->db->update($this->config['client_table'], $client, array('client_id' => $client_id));
        } else {
            $client['client_id'] = $client_id;
            $result = $this->db->insert($this->config['client_table'], $client);
        }
        return $result;
    }
    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);
            return in_array($grant_type, (array) $grant_types);
        }
        // if grant_types are not defined, then none are restricted
        return true;
    }
    /* OAuth2\Storage\AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        $token = $this->db->fetchAssoc(sprintf('SELECT * from %s where access_token = ?', $this->config['access_token_table']),
            array($access_token));
        if ($token) {
            // convert date string back to timestamp
            $token['expires'] = strtotime($token['expires']);
        }
        return $token;
    }
    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        $token = array(
            'client_id' => $client_id,
            'expires' => $expires,
            'user_id' => $user_id,
            'scope' => $scope,
            'expires' => date('Y-m-d H:i:s', $expires) 
        );

        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $result = $this->db->update($this->config['access_token_table'], $token, array('access_token' => $access_token));
        } else {
            $token['access_token'] = $access_token;
            $result = $this->db->insert($this->config['access_token_table'], $token);
        }
        return $result;
    }
    /* OAuth2\Storage\AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {

        $code = $this->db->fetchAssoc(sprintf('SELECT * from %s where authorization_code = ?', $this->config['code_table']),
            array($code));
        if ($code) {
            // convert date string back to timestamp
            $code['expires'] = strtotime($code['expires']);
        }
        return $code;
    }
    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        if (func_num_args() > 6) {
            // we are calling with an id token
            return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
        }

        $auth_code = array(
            'client_id' => $client_id,
            'user_id' => $user_id,
            'redirect_uri' => $redirect_uri,
            'expires' => date('Y-m-d H:i:s', $expires),
            'scope' => $scope
        );

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $result = $this->db->update($this->config['code_table'], $auth_code, array('authorization_code' => $code));
        } else {
            $auth_code['authorization_code'] = $code;
            $result = $this->db->insert($this->config['code_table'], $auth_code);
        }
        return $result;
    }
    private function setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        $auth_code = array(
            'client_id' => $client_id,
            'user_id' => $user_id,
            'redirect_uri' => $redirect_uri,
            'expires' => date('Y-m-d H:i:s', $expires),
            'scope' => $scope,
            'id_token' => $id_token
        );

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $result = $this->db->update($this->config['code_table'], $auth_code, array('authorization_code' => $code));
        } else {
            $auth_code['authorization_code'] = $code;
            $result = $this->db->insert($this->config['code_table'], $auth_code);
        }
        return $result;
    }
    public function expireAuthorizationCode($code)
    {
        $result = $this->db->delete($this->config['code_table'], array('authorization_code' => $code));
        return $result;
    }
    /* OAuth2\Storage\UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }
        return false;
    }
    public function getUserDetails($username)
    {
        return $this->getUser($username);
    }
    /* UserClaimsInterface */
    public function getUserClaims($user_id, $claims)
    {
        if (!$userDetails = $this->getUserDetails($user_id)) {
            return false;
        }
        $claims = explode(' ', trim($claims));
        $userClaims = array();
        // for each requested claim, if the user has the claim, set it in the response
        $validClaims = explode(' ', self::VALID_CLAIMS);
        foreach ($validClaims as $validClaim) {
            if (in_array($validClaim, $claims)) {
                if ($validClaim == 'address') {
                    // address is an object with subfields
                    $userClaims['address'] = $this->getUserClaim($validClaim, $userDetails['address'] ?: $userDetails);
                } else {
                    $userClaims = array_merge($userClaims, $this->getUserClaim($validClaim, $userDetails));
                }
            }
        }
        return $userClaims;
    }
    protected function getUserClaim($claim, $userDetails)
    {
        $userClaims = array();
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
        $claimValues = explode(' ', $claimValuesString);
        foreach ($claimValues as $value) {
            $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
        }
        return $userClaims;
    }
    /* OAuth2\Storage\RefreshTokenInterface */
    public function getRefreshToken($refresh_token)
    {
        $token = $this->db->fetchAssoc(sprintf('SELECT * FROM %s WHERE refresh_token = ?', $this->config['refresh_token_table']));
        if ($token) {
            // convert expires to epoch time
            $token['expires'] = strtotime($token['expires']);
        }
        return $token;
    }
    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        $refresh_token = array(
            'refresh_token' => $refresh_token,
            'client_id' => $client_id,
            'user_id' => $user_id,
            'expires' => date('Y-m-d H:i:s', $expires),
            'scope' => $scope
        ); 

        $result = $this->db->insert($this->config['refresh_token_table'], $refresh_token);
        return $result;
    }
    public function unsetRefreshToken($refresh_token)
    {
        $result = $this->db->delete($this->config['refresh_token_table'], array('refresh_token' => $refresh_token));
        return $result;
    }
    // plaintext passwords are bad!  Override this for your application
    protected function checkPassword($user, $password)
    {
        return $user['password'] == sha1($password);
    }
    public function getUser($username)
    {        
        $userInfo = $this->db->fetchAssoc($sql = sprintf('SELECT * from %s where username=?', $this->config['user_table']),
            array($username));
        if (!$userInfo) {
            return false;
        }
        // the default behavior is to use "username" as the user_id
        return array_merge(array(
            'user_id' => $username
        ), $userInfo);
    }
    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        $user = array(
            'password' => sha1($password),
            'first_name' => $firstName,
            'last_name' => $lastName
        );

        // if it exists, update it.
        if ($this->getUser($username)) {
            $result = $this->db->update($this->config['user_table'], $user, array('username' => $username));
        } else {
            $user['username'] = $username;
            $result = $this->db->insert($this->config['user_table'], $user);
        }
        return $result;
    }
    /* ScopeInterface */
    public function scopeExists($scope)
    {
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
        $result = $this->db->fetchAssoc(sprintf('SELECT count(scope) as count FROM %s WHERE scope IN (%s)', $this->config['scope_table'], $whereIn));
        if ($result) {
            return $result['count'] == count($scope);
        }
        return false;
    }
    public function getDefaultScope($client_id = null)
    {
        $result = $this->db->fetchAssoc(sprintf('SELECT scope FROM %s WHERE is_default=?', $this->config['scope_table']),
            array(true));
        if ($result) {
            $defaultScope = array_map(function ($row) {
                return $row['scope'];
            }, $result);
            return implode(' ', $defaultScope);
        }
        return null;
    }
    /* JWTBearerInterface */
    public function getClientKey($client_id, $subject)
    {
        $result = $this->db->fetchAssoc(sprintf('SELECT public_key from %s where client_id=:client_id AND subject=?', $this->config['jwt_table']),
            array($subject));
        return $result['public_key'];
    }
    public function getClientScope($client_id)
    {
        if (!$clientDetails = $this->getClientDetails($client_id)) {
            return false;
        }
        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }
        return null;
    }
    public function getJti($client_id, $subject, $audience, $expires, $jti)
    {        
        $result = $this->db->fetchAssoc(sprintf('SELECT * FROM %s WHERE issuer=? AND subject=? AND audience=? AND expires=? AND jti=?', $this->config['jti_table']),
            array($client_id, $subject, $audience, $expires, $jti));
        if ($result) {
            return array(
                'issuer' => $result['issuer'],
                'subject' => $result['subject'],
                'audience' => $result['audience'],
                'expires' => $result['expires'],
                'jti' => $result['jti'],
            );
        }
        return null;
    }
    public function setJti($client_id, $subject, $audience, $expires, $jti)
    {
        $jti = array(
            'issuer' => $client_id,
            'subject' => $subject,
            'audience' => $audience,
            'expires' => $expires,
            'jti' => $jti
        );

        $result = $this->db->insert($this->config['jti_table'], $jti);
        return $result;
    }
    /* PublicKeyInterface */
    public function getPublicKey($client_id = null)
    {
        $result = $this->db->fetchAssoc(sprintf('SELECT public_key FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']),
            array($client_id));
        if ($result) {
            return $result['public_key'];
        }
    }
    public function getPrivateKey($client_id = null)
    {
        $result = $this->db->fetchAssoc(sprintf('SELECT private_key FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']),
            array($client_id));
        if ($result) {
            return $result['private_key'];
        }
    }
    public function getEncryptionAlgorithm($client_id = null)
    {
        $result = $this->db->fetchAssoc(sprintf('SELECT encryption_algorithm FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']),
            array($client_id));
        if ($result) {
            return $result['encryption_algorithm'];
        }
        return 'RS256';
    }
    /**
     * DDL to create OAuth2 database and tables for PDO storage
     *
     * @see https://github.com/dsquier/oauth2-server-php-mysql
     */
    public function getBuildSql($dbName = 'oauth2_server_php')
    {
        $sql = "
        CREATE TABLE {$this->config['client_table']} (
          client_id             VARCHAR(80)   NOT NULL,
          client_secret         VARCHAR(80)   NOT NULL,
          redirect_uri          VARCHAR(2000),
          grant_types           VARCHAR(80),
          scope                 VARCHAR(4000),
          user_id               VARCHAR(80),
          PRIMARY KEY (client_id)
        );
        CREATE TABLE {$this->config['access_token_table']} (
          access_token         VARCHAR(40)    NOT NULL,
          client_id            VARCHAR(80)    NOT NULL,
          user_id              VARCHAR(80),
          expires              TIMESTAMP      NOT NULL,
          scope                VARCHAR(4000),
          PRIMARY KEY (access_token)
        );
        CREATE TABLE {$this->config['code_table']} (
          authorization_code  VARCHAR(40)    NOT NULL,
          client_id           VARCHAR(80)    NOT NULL,
          user_id             VARCHAR(80),
          redirect_uri        VARCHAR(2000),
          expires             TIMESTAMP      NOT NULL,
          scope               VARCHAR(4000),
          id_token            VARCHAR(1000),
          PRIMARY KEY (authorization_code)
        );
        CREATE TABLE {$this->config['refresh_token_table']} (
          refresh_token       VARCHAR(40)    NOT NULL,
          client_id           VARCHAR(80)    NOT NULL,
          user_id             VARCHAR(80),
          expires             TIMESTAMP      NOT NULL,
          scope               VARCHAR(4000),
          PRIMARY KEY (refresh_token)
        );
        CREATE TABLE {$this->config['user_table']} (
          username            VARCHAR(80),
          password            VARCHAR(80),
          first_name          VARCHAR(80),
          last_name           VARCHAR(80),
          email               VARCHAR(80),
          email_verified      BOOLEAN,
          scope               VARCHAR(4000)
        );
        CREATE TABLE {$this->config['scope_table']} (
          scope               VARCHAR(80)  NOT NULL,
          is_default          BOOLEAN,
          PRIMARY KEY (scope)
        );
        CREATE TABLE {$this->config['jwt_table']} (
          client_id           VARCHAR(80)   NOT NULL,
          subject             VARCHAR(80),
          public_key          VARCHAR(2000) NOT NULL
        );
        
        CREATE TABLE {$this->config['jti_table']} (
          issuer              VARCHAR(80)   NOT NULL,
          subject             VARCHAR(80),
          audiance            VARCHAR(80),
          expires             TIMESTAMP     NOT NULL,
          jti                 VARCHAR(2000) NOT NULL
        );
        CREATE TABLE {$this->config['public_key_table']} (
          client_id            VARCHAR(80),
          public_key           VARCHAR(2000),
          private_key          VARCHAR(2000),
          encryption_algorithm VARCHAR(100) DEFAULT 'RS256'
        )
";
        return $sql;
    }
}