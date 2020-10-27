(herald "TLS 1.3 Protocol Analyser"
        (algebra diffie-hellman))


;;using macros for handshake property(pg 62)      
;;(defmacro (handshake n a b)                     

;;  (^ (send (enc "hello" a b n (pubk b))) (recv \(enc "hello-received" a n (pubk a))))             

;;working of the protocol using psk               

(defprotocol tls diffie-hellman

 ;; client side                                  
 (defrole init
 (vars (a b name)(m text)(psk skey))
  (trace
   (send (enc "hello" a b psk))
   (recv (enc "hello-received" a psk))))

 ;;server side                                   
 (defrole resp
  (vars (a b name)(m text)(psk skey))
   (trace                        
    (recv (enc "hello" a b psk))
    (send (enc "hello-received" a psk)))))

;;skeleton for client point of view              
(defskeleton tls
  (vars (a b name)(psk skey))
  (defstrand init 2 (a a)(b b)(psk psk))
  ;;(defstrand mal 3 (b b)(a a)                  
  (non-orig psk))
;;(pen-non-orig psk))                           
(defskeleton tls
  (vars (a b name)(psk skey))
  (defstrand resp 2 (b b)(a a)(psk psk))
  (non-orig psk))

(defskeleton tls
  (vars (a b name)(psk skey))
  (defstrand init 2 (a a)(b b)(psk psk))
  ;;(defstrand mal 3 (b b)(a a)                  
  (non-orig psk))
;;(pen-non-orig psk))                             
(defskeleton tls
  (vars (a b name)(psk skey))
  (defstrand resp 2 (b b)(a a)(psk psk))
  (non-orig psk))
