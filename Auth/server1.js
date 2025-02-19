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
        uid: "tom",
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

]

console.log("server is running");
app.post('/login',async (req,res)=>{
    const user = users.find(user=> user.uid === req.body.uid);
    if(user === null){
        return res.status(400).send("counld not find user");
    }
    try{
     if(await bcrypt.compare(req.body.pwd,user.pwd)){
            const uid  = req.body.uid
            const jwtuser = { uid: user.uid }; // Only include non-sensitive data
            const acesstoken = JWT.sign(jwtuser, process.env.ACCESS_TOKEN_SECRET);
            res.json({accessToken: acesstoken})
            res.send("login successful.")
       }
       else{
           res.send("Access denied")
       }
      //  users.push(user)
        res.status(201).send()
    }
    catch{

    }
})

app.post('/users',async (req,res)=>{
    // const user = users.find(user=> user.uid === req.body.uid) ;
    // if(user === null){
    //     return res.status(400).send("counld not find user");
    // }
   // console.log(user)
    try {
        // console.log("request pwd :" +  req.body.pwd);
        // console.log("user pass : " + user.pwd);
        // console.log(await bcrypt.compare(req.body.pwd,user.pwd))
           // const salt = await bcrypt.genSalt()
            const HashedPwd = await bcrypt.hash(req.body.pwd,10)
           
            console.log(HashedPwd)
            const user = {uid : req.body.uid, pwd : HashedPwd}
           
            users.push(user)
            res.status(201).send()
 
   }catch{
        res.status(500).send()
   }
    
})

app.get(
    '/users',(req,res)=>{
        res.json(users);
    }
)

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    //console.log('Auth Header:', authHeader);
    //console.log("authHeader split : ",authHeader.split(' ')[1])
    
    //const accessToken = authHeader && authHeader.split(' ')[1];   same as the following ternary operator line.
    const accessToken = authHeader?authHeader.split(' ')[1]:null;
    //console.log('Access Token:', accessToken);

    if (accessToken == null) {
        return res.status(401).send('No access token provided.');
    }

    JWT.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
        if (error) {
            console.error('JWT verification error:', error);
            return res.status(403).send('Token is invalid.');
        }
       // console.log(user)
        req.user = user;
        next();
    });
}

app.get(
    '/orders',verifyToken,(req,res)=>{
       // console.log(req.user.uid)
        res.json(orders.filter(order=>order.uid===req.user.uid))
       
    }
)
app.listen(3000);