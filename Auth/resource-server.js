import express from "express"
import bcrypt from "bcrypt"
import JWT from "jsonwebtoken"
import {config} from "dotenv"
config()
const app = express()
app.use(express.json())

const orders = [
    {
        id:' 1023',
        uid: "newuser",
        items : [
            {
                name: "HFS lightweight Road Running", 
                single_price: "105.20",
                currency : "USD",
                count : "2 "
            }
        ]
 
    }
]
const users  = [
    {
            uid : 'hashi',
            pwd : 'aa49fsdl'
    },
    {
        uid : 'han',
        pwd : 'd49pkd92'
    }, 
    {
        uid: 'newuser',
        pwd: 'password123'
    }

]

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];   
    //const accessToken = authHeader && authHeader.split(' ')[1];   same as the following ternary operator line.
    const accessToken = authHeader?authHeader.split(' ')[1]:null;
    if (accessToken == null) {
        return res.status(401).send('No access token provided.');
    }
     JWT.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
        if (error) {
            console.error('JWT verification error:', error);
            return res.status(403).send('Token is invalid.');
        }
        req.user = user;
        next();
    });
}
app.get(
    '/orders',verifyToken,(req,res)=>{
        res.json(orders.filter(order=>order.uid===req.user.uid))
       
    }
)
app.listen(3000);