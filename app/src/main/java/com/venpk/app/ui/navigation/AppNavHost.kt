package com.venpk.app.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.venpk.app.ui.screens.AboutScreen
import com.venpk.app.ui.screens.DetailScreen
import com.venpk.app.ui.screens.HomeScreen
import com.venpk.app.ui.screens.SettingsScreen

object Routes {
    const val HOME = "home"
    const val SETTINGS = "settings"
    const val ABOUT = "about"
    const val DETAIL = "detail/{itemId}"
}

@Composable
fun AppNavHost(navController: NavHostController = rememberNavController()) {
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    NavHost(
        navController = navController,
        startDestination = Routes.HOME
    ) {
        composable(Routes.HOME) {
            HomeScreen(
                onNavigateToDetail = { itemId ->
                    navController.navigate("detail/$itemId")
                },
                onNavigateToSettings = {
                    navController.navigate(Routes.SETTINGS)
                },
                onNavigateToAbout = {
                    navController.navigate(Routes.ABOUT)
                }
            )
        }

        composable(Routes.SETTINGS) {
            SettingsScreen(onBack = { navController.popBackStack() })
        }

        composable(Routes.ABOUT) {
            AboutScreen(onBack = { navController.popBackStack() })
        }

        composable(
            route = Routes.DETAIL,
            arguments = listOf(navArgument("itemId") { type = NavType.IntType })
        ) { backStackEntry ->
            val itemId = backStackEntry.arguments?.getInt("itemId") ?: 0
            DetailScreen(
                itemId = itemId,
                onBack = { navController.popBackStack() }
            )
        }
    }
}
