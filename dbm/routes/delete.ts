import { Router } from "express";
import { supabase } from "../lib";
import { UserResponse } from "@supabase/supabase-js";

export const router = Router()

router.get('/user/:id', async (req, res) => {
    const result = await supabase.from('radcheck').delete().eq('id', req.params.id).select().single()
    if (result.error) {
        res.status(422).json(result.error);
        return
    }
    res.status(200).json(result.data)
})

router.get('/:id', async (req, res) => {
    const result: UserResponse = await supabase.auth.admin.deleteUser(req.params.id)
    if (result.error) {
        res.status(422).json(result.error);
        return
    }
    res.status(200).json(result.data)
})