import { Router } from "express";
import { supabase } from "../lib";

export const router = Router()

router.get('/user/:id', async (req, res) => {
    const result = await supabase.from('radcheck').select('*').eq('id', req.params.id).single()
    if (result.error) {
        res.status(422).json(result.error);
        return
    }
    res.status(200).json(result.data)
})

// Expects the the company id, and returns all current users of the company
router.get('/company/users/:id', async (req, res) => {
    const result = await supabase.from('radcheck').select(`
        *,
        companies(
            id
        )
    `).eq('companies.id', req.params.id)
    if (result.error) {
        res.status(422).json(result.error);
        return
    }
    return res.status(200).json(result.data)
})

router.get('/company/:id', async (req, res) => {
    const result = await supabase.from('companies').select('*').eq('id', req.params.id)
    if (result.error) {
        res.status(422).send('Invalid id');
        return
    }
    res.status(200).json(result.data)
})

router.get('/third-party/:id', async (req, res) => {
    const result = await supabase.from('nas').select('*').eq('id', req.params.id)
    if (result.error) {
        res.status(422).json(result.error);
        return
    }
    res.status(200).json(result.data)
})