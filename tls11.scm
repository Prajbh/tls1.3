(herald "TLS 1.3 Protocol Analyser"
	(algebra diffie-hellman))

;;working of the protocol using psk              

(defprotocol tls diffie-hellman
  (defrole initialize
    (vars (psk skey)(index text))
    (trace
     (init (cat psk index)))
    (uniq-gen psk index))
 ;; client side                                  
 (defrole init
   (vars (a b name)(m d text)(psk skey)(index text))
   (trace
    ;;(send a)
    ;;(recv index)
    (obsv (cat psk index))
    (send (cat "Client-hello" index))
    (recv (cat "Server-hello" (hash "Client-hello" index "finsihed" psk)))
    (send (hash "Client-hello" (hash "Client-hello" index "finished" psk) psk))))
   ;;(recv (cat "hello-received" index)
   

 ;;server side                                   
 (defrole resp
  (vars (a b name)(m d text)(psk k skey)(index text))
   (trace
    ;;(recv a)
    (obsv (cat psk index))
    ;;(send index)
    (recv (cat "Client-hello" index))
    (send (cat "Server-hello" (hash "Client-hello" index "finsihed" psk)))
    (recv (hash "Client-hello" (hash "Client-hello" index "finished" psk) psk)))))

;;skeleton for client point of view              
(defskeleton tls
  (vars (a name)(psk k skey)(index text))
  (defstrand init 4 (psk psk)(index index))
  ;;(defstrand mal 3 (b b)(a a)                  
  (non-orig psk))
  ;;)
;;(pen-non-orig psk))                           
(defskeleton tls
  (vars (a b name)(psk k skey)(index text))
  (defstrand resp 4 (psk psk)(index index))
  (non-orig psk))
;;)

;(defskeleton tls
;  (vars (a name)(psk skey))
;  (defstrand init 3 (a a)(psk psk))
;  (defstrand resp 3 (a b)(b a)(psk psk))         
;  (non-orig psk))
;;(pen-non-orig psk))                             
;(defskeleton tls
;  (vars (a b name)(psk skey))
;  (defstrand resp 2 (b b)(a a)(psk psk))
;  (non-orig psk))
